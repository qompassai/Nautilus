#!/usr/bin/env python3
#
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute
# it and/or modify it under the terms of GPLv2

import logging
import sys
from datetime import datetime
from hashlib import md5
from json import JSONDecodeError, dumps, loads
from os.path import abspath, dirname

from azure.common import AzureException, AzureHttpError
from azure.storage.blob import BlockBlobService
from azure.storage.common._error import AzureSigningError
from azure.storage.common.retry import no_retry
from dateutil.parser import parse

sys.path.insert(0, dirname(dirname(abspath(__file__))))

from azure_utils import (
    CREDENTIALS_URL,
    DEPRECATED_MESSAGE,
    offset_to_datetime,
    read_auth_file,
    send_message,
)
from db import orm
from db.utils import create_new_row, update_row_object


def start_storage(args):
    """Get access and content of the storage accounts."""
    logging.info('Azure Storage starting.')

    # Read credentials
    logging.info('Storage: Authenticating.')
    if args.storage_auth_path:
        logging.debug(f"Storage: Using path {args.storage_auth_path} for authentication")
        name, key = read_auth_file(
            auth_path=args.storage_auth_path, fields=('account_name', 'account_key')
        )
    elif args.account_name and args.account_key:
        logging.debug(f"Storage: Using path account name and account key for authentication")
        logging.warning(
            DEPRECATED_MESSAGE.format(
                name='account_name and account_key', release='4.4', url=CREDENTIALS_URL
            )
        )
        name = args.account_name
        key = args.account_key
    else:
        logging.error('Storage: No parameters have been provided for authentication.')
        sys.exit(1)

    block_blob_service = BlockBlobService(account_name=name, account_key=key)

    # Disable max retry value before attempting to validate the credentials
    old_retry_value = block_blob_service.retry
    block_blob_service.retry = no_retry

    # Verify if the credentials grant access to the specified container
    if args.container != '*':
        try:
            if not block_blob_service.exists(args.container):
                logging.error(
                    f'Storage: The "{args.container}" container does not exists.'
                )
                sys.exit(1)
            logging.info(f"Storage: Getting the specified containers: {args.container}")
            containers = [args.container]
        except AzureException:
            logging.error(
                f'Storage: Invalid credentials for accessing the "{args.container}" container.'
            )
            sys.exit(1)
    else:
        try:
            logging.info("Storage: Getting all containers.")
            containers = [
                container.name for container in block_blob_service.list_containers()
            ]
        except AzureSigningError:
            logging.error(
                'Storage: Unable to list the containers. Invalid credentials.'
            )
            sys.exit(1)
        except AzureException as e:
            logging.error(f'Storage: The containers could not be listed: "{e}".')
            sys.exit(1)

    # Restore the default max retry value
    block_blob_service.retry = old_retry_value
    logging.info('Storage: Authenticated.')

    # Get the blobs
    for container in containers:
        md5_hash = md5(name.encode()).hexdigest()
        offset = args.storage_time_offset
        try:
            item = orm.get_row(orm.Storage, md5=md5_hash)
            if item is None:
                item = create_new_row(
                    table=orm.Storage, query=name, md5_hash=md5_hash, offset=offset
                )
        except orm.AzureORMError as e:
            logging.error(
                f'Error trying to obtain row object from "{orm.Storage.__tablename__}" using md5="{md5}": {e}'
            )
            sys.exit(1)

        min_datetime = parse(item.min_processed_date, fuzzy=True)
        max_datetime = parse(item.max_processed_date, fuzzy=True)
        desired_datetime = offset_to_datetime(offset) if offset else max_datetime
        get_blobs(
            container_name=container,
            prefix=args.prefix,
            blob_service=block_blob_service,
            md5_hash=md5_hash,
            min_datetime=min_datetime,
            max_datetime=max_datetime,
            desired_datetime=desired_datetime,
            tag=args.storage_tag,
            reparse=args.reparse,
            json_file=args.json_file,
            json_inline=args.json_inline,
            blob_extension=args.blobs,
        )
    logging.info('Storage: End')


def get_blobs(
    container_name: str,
    blob_service: BlockBlobService,
    md5_hash: str,
    min_datetime: datetime,
    max_datetime: datetime,
    desired_datetime: datetime,
    tag: str,
    reparse: bool,
    json_file: bool,  # CHECKME
    json_inline: bool,  # CHECKME
    blob_extension: str,
    next_marker: str = None,
    prefix: str = None,
):
    """Get the blobs from a container and send their content.

    Parameters
    ----------
    container_name : str
        Name of container to read the blobs from.
    blob_service : BlockBlobService
        Client used to obtain the blobs.
    min_datetime : datetime
        Value to compare with the blobs last modified times.
    max_datetime : datetime
        Value to compare with the blobs last modified times.
    desired_datetime : datetime
        Value to compare with the blobs last modified times.
    md5_hash : str
        md5 value used to search the container in the file containing the dates.
    next_marker : str
        Token used as a marker to continue from previous iteration.
    prefix : str, optional
        Prefix value to search blobs that match with it.

    Raises
    ------
    AzureException
        If it was not possible to list the blobs for the given container.
    """
    try:
        # Get the blob list
        logging.info(f"Storage: Getting blobs from container {container_name}.")
        blobs = blob_service.list_blobs(
            container_name, prefix=prefix, marker=next_marker
        )
    except AzureException as e:
        logging.error(f'Storage: Error getting blobs from "{container_name}": "{e}".')
        raise e
    else:

        logging.info(
            f'Storage: The search starts from the date: {desired_datetime} for blobs in '
            f'container: "{container_name}" and prefix: "/{prefix if prefix is not None else ""}"'
        )
        for blob in blobs:
            # Skip if the blob is empty
            if blob.properties.content_length == 0:
                logging.debug(f'Empty blob {blob.name}, skipping')
                continue
            # Skip the blob if nested under the set prefix
            if prefix is not None and len(blob.name.split('/')) > 2:
                logging.debug(
                    f'Skipped blob {blob.name}, nested under set prefix {prefix}'
                )
                continue
            # Skip the blob if its name has not the expected format
            if blob_extension and blob_extension not in blob.name:
                logging.debug(
                    f'Skipped blob, name {blob.name} does not match with the format "{blob_extension}"'
                )
                continue

            # Skip the blob if already processed
            last_modified = blob.properties.last_modified
            if not reparse and (
                last_modified < desired_datetime
                or (min_datetime <= last_modified <= max_datetime)
            ):
                logging.info(f"Storage: Skipping blob {blob.name} due to being already processed")
                continue

            # Get the blob data
            try:
                logging.info(f"Getting data from blob {blob.name}")
                data = blob_service.get_blob_to_text(container_name, blob.name)
            except (ValueError, AzureException, AzureHttpError) as e:
                logging.error(f'Storage: Error reading the blob data: "{e}".')
                continue
            else:
                # Process the data as a JSON
                if json_file:
                    try:
                        content_list = loads(data.content)
                        records = content_list['records']
                    except (JSONDecodeError, TypeError) as e:
                        logging.error(
                            f'Storage: Error reading the contents of the blob: "{e}".'
                        )
                        continue
                    except KeyError as e:
                        logging.error(
                            f'Storage: No records found in the blob\'s contents: "{e}".'
                        )
                        continue
                    else:
                        for log_record in records:
                            # Add azure tags
                            log_record['azure_tag'] = 'azure-storage'
                            if tag:
                                log_record['azure_storage_tag'] = tag
                            logging.info('Storage: Sending event by socket.')
                            send_message(dumps(log_record))
                # Process the data as plain text
                else:
                    for line in [s for s in str(data.content).splitlines() if s]:
                        if json_inline:
                            msg = '{"azure_tag": "azure-storage"'
                            if tag:
                                msg = f'{msg}, "azure_storage_tag": "{tag}"'
                            msg = f'{msg}, {line[1:]}'
                        else:
                            msg = 'azure_tag: azure-storage.'
                            if tag:
                                msg = f'{msg} azure_storage_tag: {tag}.'
                            msg = f'{msg} {line}'
                        logging.info('Storage: Sending event by socket.')
                        send_message(msg)
            update_row_object(
                table=orm.Storage,
                md5_hash=md5_hash,
                query=container_name,
                new_min=last_modified.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                new_max=last_modified.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            )

        # Continue until no marker is returned
        if blobs.next_marker:
            logging.debug(f"Iteration to next marker: {blobs.next_marker}")
            get_blobs(
                container_name=container_name,
                blob_service=blob_service,
                next_marker=blobs.next_marker,
                min_datetime=min_datetime,
                max_datetime=max_datetime,
                desired_datetime=desired_datetime,
                md5_hash=md5_hash,
                tag=tag,
                reparse=reparse,
                json_file=json_file,
                json_inline=json_inline,
                blob_extension=blob_extension,
            )
