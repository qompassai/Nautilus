/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/* An extremely basic ring buffer implemented as a complete header in pure C; 
 * for use with datasource implementations in C */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "simple_ringbuf_c.h"

/* Allocate a ring buffer
 *
 * Returns NULL if allocation failed
 */
kis_simple_ringbuf_t *kis_simple_ringbuf_create(size_t size) {
    kis_simple_ringbuf_t *rb;
    rb = (kis_simple_ringbuf_t *) malloc(sizeof(kis_simple_ringbuf_t));

    if (rb == NULL)
        return NULL;

    rb->buffer = (uint8_t *) malloc(size);

    if (rb->buffer == NULL) {
        free(rb);
        return NULL;
    }

    rb->buffer_sz = size;
    rb->start_pos = 0;
    rb->length = 0;
    rb->mid_peek = 0;
    rb->mid_commit = 0;
    rb->free_peek = 0;
    rb->free_commit = 0;

    return rb;
}

/* Destroy a ring buffer
 */
void kis_simple_ringbuf_free(kis_simple_ringbuf_t *ringbuf) {
    free(ringbuf->buffer);
    free(ringbuf);
}

/* Clear ring buffer
 */
void kis_simple_ringbuf_clear(kis_simple_ringbuf_t *ringbuf) {
    ringbuf->start_pos = 0;
    ringbuf->length = 0;
}

/* Get available space
 */
size_t kis_simple_ringbuf_available(kis_simple_ringbuf_t *ringbuf) {
    return ringbuf->buffer_sz - ringbuf->length;
}

/* Get used space
 */
size_t kis_simple_ringbuf_used(kis_simple_ringbuf_t *ringbuf) {
    return ringbuf->length;
}

/* Get total space
 * */
size_t kis_simple_ringbuf_size(kis_simple_ringbuf_t *ringbuf) {
    return ringbuf->buffer_sz;
}

/* Append data
 *
 * Returns amount written
 */
size_t kis_simple_ringbuf_write(kis_simple_ringbuf_t *ringbuf, 
        void *data, size_t length) {
    size_t copy_start;

    if (kis_simple_ringbuf_available(ringbuf) < length)
        return 0;

    copy_start = 
        (ringbuf->start_pos + ringbuf->length) % ringbuf->buffer_sz;

    /* Does the write op fit w/out looping? */
    if (copy_start + length < ringbuf->buffer_sz) {
        memcpy(ringbuf->buffer + copy_start, data, length);
        ringbuf->length += length;

        return length;
    } else {
        /* We have to split up, figure out the length of the two chunks */
        size_t chunk_a = ringbuf->buffer_sz - copy_start;
        size_t chunk_b = length - chunk_a;

        memcpy(ringbuf->buffer + ringbuf->start_pos + ringbuf->length, data, chunk_a);
        memcpy(ringbuf->buffer, (uint8_t *) data + chunk_a, chunk_b);

        /* Increase the length of the buffer */
        ringbuf->length += length;

        return length;
    }

    return 0;
}

size_t kis_simple_ringbuf_reserve(kis_simple_ringbuf_t *ringbuf, void **data, size_t size) {
    size_t copy_start;

    if (kis_simple_ringbuf_available(ringbuf) < size)
        return 0;

    if (ringbuf->mid_commit) {
        fprintf(stderr, "ERROR: kis_simple_ringbuf_t mid-commit when reserve called\n");
        return 0;
    }

    copy_start = 
        (ringbuf->start_pos + ringbuf->length) % ringbuf->buffer_sz;

    /* Does the write op fit w/out looping? */
    if (copy_start + size < ringbuf->buffer_sz) {
        ringbuf->mid_commit = 1;
        ringbuf->free_commit = 0;
        *data = ringbuf->buffer + copy_start;
        return size;
    } else {
        *data = malloc(size);

        if (*data == NULL) {
            fprintf(stderr, "ERROR:  Could not allocate split-op sz write buffer\n");
            return 0;
        }

        ringbuf->mid_commit = 1;
        ringbuf->free_commit = 1;

        return size;
    }

    return 0;
}

size_t kis_simple_ringbuf_commit(kis_simple_ringbuf_t *ringbuf, void *data, size_t size) {
    if (!ringbuf->mid_commit) {
        fprintf(stderr, "ERROR: kis_simple_ringbuf_t not in a commit when commit called\n");
        return 0;
    }

    size_t copy_start;

    copy_start = 
        (ringbuf->start_pos + ringbuf->length) % ringbuf->buffer_sz;

    if (!ringbuf->free_commit) {
        ringbuf->mid_commit = 0;
        ringbuf->length += size;
        return size;
    } else {
        /* Does the write op fit w/out looping? */
        if (copy_start + size < ringbuf->buffer_sz) {
            memcpy(ringbuf->buffer + copy_start, data, size);
            ringbuf->length += size;

            return size;
        } else {
            /* We have to split up, figure out the length of the two chunks */
            size_t chunk_a = ringbuf->buffer_sz - copy_start;
            size_t chunk_b = size - chunk_a;

            memcpy(ringbuf->buffer + ringbuf->start_pos + ringbuf->length, data, chunk_a);
            memcpy(ringbuf->buffer, (uint8_t *) data + chunk_a, chunk_b);

            /* Increase the length of the buffer */
            ringbuf->length += size;

            return size;
        }
    }

    return 0;
}

/* Free a previously reserved chunk without committing it.
 */
void kis_simple_ringbuf_reserve_free(kis_simple_ringbuf_t *ringbuf, void *data) {
    if (!ringbuf->mid_commit) {
        fprintf(stderr, "ERROR: kis_simple_ringbuf_t not in a commit when commit_reserve_free called\n");
    }

    if (ringbuf->free_commit)
        free(data);

    ringbuf->mid_commit = 0;
}

/* Copies data into provided buffer.  Advances ringbuf, clearing consumed data.
 *
 * If requested amount is not available, reads amount available and returns.
 *
 * Returns amount copied
 */
size_t kis_simple_ringbuf_read(kis_simple_ringbuf_t *ringbuf, void *ptr, 
        size_t size) {
    /* Start with how much we have available - no matter what was
     * requested, we can't read more than this */
    size_t opsize = kis_simple_ringbuf_used(ringbuf);

    if (opsize == 0)
        return 0;

    /* Only read the amount we requested, if more is available */
    if (opsize > size)
        opsize = size;

    /* Simple contiguous read */
    if (ringbuf->start_pos + opsize < ringbuf->buffer_sz) {
        if (ptr != NULL)
            memcpy(ptr, ringbuf->buffer + ringbuf->start_pos, opsize);
        ringbuf->start_pos += opsize;
        ringbuf->length -= opsize;
        return opsize;
    } else {
        /* First chunk, start to end of buffer */
        size_t chunk_a = ringbuf->buffer_sz - ringbuf->start_pos;
        /* Second chunk, 0 to remaining data */
        size_t chunk_b = opsize - chunk_a;

        if (ptr != NULL) {
            memcpy(ptr, ringbuf->buffer + ringbuf->start_pos, chunk_a);
            memcpy((uint8_t *) ptr + chunk_a, ringbuf->buffer, chunk_b);
        }

        /* Fastforward around the ring to where we finished reading */
        ringbuf->start_pos = chunk_b;
        ringbuf->length -= opsize;

        return opsize;
    }

    return 0;
}

/* Peeks at data by copying into provided buffer.  Does NOT advance ringbuf
 * or consume data.
 *
 * If requested amount of data is not available, peeks amount available and 
 * returns;
 *
 * Returns amount copied
 */
size_t kis_simple_ringbuf_peek(kis_simple_ringbuf_t *ringbuf, void *ptr, 
        size_t size) {
    /* Start with how much we have available - no matter what was
     * requested, we can't read more than this */
    size_t opsize = kis_simple_ringbuf_used(ringbuf);

    if (opsize == 0)
        return 0;

    /* Only read the amount we requested, if more is available */
    if (opsize > size)
        opsize = size;

    /* Simple contiguous read */
    if (ringbuf->start_pos + opsize < ringbuf->buffer_sz) {
        memcpy(ptr, ringbuf->buffer + ringbuf->start_pos, opsize);
        return opsize;
    } else {
        /* First chunk, start to end of buffer */
        size_t chunk_a = ringbuf->buffer_sz - ringbuf->start_pos;
        /* Second chunk, 0 to remaining data */
        size_t chunk_b = opsize - chunk_a;

        memcpy(ptr, ringbuf->buffer + ringbuf->start_pos, chunk_a);
        memcpy((uint8_t *) ptr + chunk_a, ringbuf->buffer, chunk_b);

        return opsize;
    }

    return 0;
}

size_t kis_simple_ringbuf_peek_zc(kis_simple_ringbuf_t *ringbuf, void **ptr, size_t size) {
    /* Start with how much we have available - no matter what was
     * requested, we can't read more than this */
    size_t opsize = kis_simple_ringbuf_used(ringbuf);

    if (ringbuf->mid_peek) {
        fprintf(stderr, "ERROR: simple_ringbuf_peek_zc mid-peek already\n");
        return 0;
    }

    if (opsize == 0)
        return 0;

    /* Only read the amount we requested, if more is available */
    if (opsize > size)
        opsize = size;

    /* Simple contiguous read */
    if (ringbuf->start_pos + opsize < ringbuf->buffer_sz) {
        ringbuf->mid_peek = 1;
        ringbuf->free_peek = 0;
        *ptr = ringbuf->buffer + ringbuf->start_pos;
        return opsize;
    } else {
        /* First chunk, start to end of buffer */
        size_t chunk_a = ringbuf->buffer_sz - ringbuf->start_pos;
        /* Second chunk, 0 to remaining data */
        size_t chunk_b = opsize - chunk_a;

        *ptr = malloc(opsize);

        if (*ptr == NULL) {
            fprintf(stderr, "ERROR: simple_ringbuf_peek_zc could not allocate buffer for split peek\n");
            return 0;
        }

        ringbuf->mid_peek = 1;
        ringbuf->free_peek = 1;

        memcpy(*ptr, ringbuf->buffer + ringbuf->start_pos, chunk_a);
        memcpy((uint8_t *) *ptr + chunk_a, ringbuf->buffer, chunk_b);

        return opsize;
    }

    return 0;
}

void kis_simple_ringbuf_peek_free(kis_simple_ringbuf_t *ringbuf, void *ptr) {
    if (!ringbuf->mid_peek) {
        fprintf(stderr, "ERROR: kis_simple_ringbuf_peek_free called with no peeked data\n");
        return;
    }

    if (ringbuf->free_peek)
        free(ptr);

    ringbuf->mid_peek = 0;
}

