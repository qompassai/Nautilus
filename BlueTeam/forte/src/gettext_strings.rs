use gettext_macros::t;

fn _dummy() {
    t!("Error");
    t!("Looks like something went wrong :(");
    t!("Error message: {{ internal_error }}");
    t!("There was an error with your request:");
    t!("We found an entry for <span class=\"email\">{{ query }}</span>:");
    t!("<strong>Hint:</strong> It's more convenient to use <span class=\"brand\">forte.qompass.ai</span> from your PGP/GPG software.<br /> Take a look at our <a href=\"/about/usage\">usage guide</a> for details.");
    t!("debug info");
    t!("Search by Email Address / Key ID / Fingerprint");
    t!("Search");
    t!("You can also <a href=\"/upload\">upload</a> or <a href=\"/manage\">manage</a> your key.");
    t!("Find out more <a href=\"/about\">about this service</a>.");
    t!("News:");
    t!("<a href=\"/about/news#2019-11-12-celebrating-100k\">Celebrating 100.000 verified addresses! 📈</a> (2019-11-12)");
    t!("v{{ version }} built from");
    t!("Powered by <a href=\"https://sequoia-pgp.org\">Sequoia-PGP</a>");
    t!("Background image retrieved from <a href=\"https://www.toptal.com/designers/subtlepatterns/subtle-grey/\">Subtle Patterns</a> under CC BY-SA 3.0");
    t!("Maintenance Mode");
    t!("Manage your key");
    t!("Enter any verified email address for your key");
    t!("Send link");
    t!("We will send you an email with a link you can use to remove any of your email addresses from search.");
    t!("Managing the key <span class=\"fingerprint\"><a href=\"{{ key_link }}\" target=\"_blank\">{{ key_fpr }}</a></span>.");
    t!("Your key is published with the following identity information:");
    t!("Delete");
    t!("Clicking \"delete\" on any address will remove it from this key. It will no longer appear in a search.<br /> To add another address, <a href=\"/upload\">upload</a> the key again.");
    t!("Your key is published as only non-identity information.  (<a href=\"/about\" target=\"_blank\">What does this mean?</a>)");
    t!("To add an address, <a href=\"/upload\">upload</a> the key again.");
    t!("We have sent an email with further instructions to <span class=\"email\">{{ address }}</span>.");
    t!("This address has already been verified.");
    t!("Your key <span class=\"fingerprint\">{{ key_fpr }}</span> is now published for the identity <a href=\"{{userid_link}}\" target=\"_blank\"><span class=\"email\">{{ userid }}</span></a>.");
    t!("Upload your key");
    t!("Upload");
    t!("Need more info? Check our <a target=\"_blank\" href=\"/about\">intro</a> and <a target=\"_blank\" href=\"/about/usage\">usage guide</a>.");
    t!("You uploaded the key <span class=\"fingerprint\"><a href=\"{{ key_link }}\" target=\"_blank\">{{ key_fpr }}</a></span>.");
    t!("This key is revoked.");
    t!("It is published without identity information and can't be made available for search by email address (<a href=\"/about\" target=\"_blank\">what does this mean?</a>).");
    t!("This key is now published with the following identity information (<a href=\"/about\" target=\"_blank\">what does this mean?</a>):");
    t!("Published");
    t!("This key is now published with only non-identity information. (<a href=\"/about\" target=\"_blank\">What does this mean?</a>)");
    t!("To make the key available for search by email address, you can verify it belongs to you:");
    t!("Verification Pending");
    t!("<strong>Note:</strong> Some providers delay emails for up to 15 minutes to prevent spam. Please be patient.");
    t!("Send Verification Email");
    t!("This key contains one identity that could not be parsed as an email address.<br /> This identity can't be published on <span class=\"brand\">forte.qompass.ai</span>.  (<a href=\"/about/faq#non-email-uids\" target=\"_blank\">Why?</a>)");
    t!("This key contains {{ count_unparsed }} identities that could not be parsed as an email address.<br /> These identities can't be published on <span class=\"brand\">forte.qompass.ai</span>.  (<a href=\"/about/faq#non-email-uids\" target=\"_blank\">Why?</a>)");
    t!("This key contains one revoked identity, which is not published. (<a href=\"/about/faq#revoked-uids\" target=\"_blank\">Why?</a>)");
    t!("This key contains {{ count_revoked }} revoked identities, which are not published. (<a href=\"/about/faq#revoked-uids\" target=\"_blank\">Why?</a>)");
    t!("Your keys have been successfully uploaded:");
    t!("<strong>Note:</strong> To make keys searchable by email address, you must upload them individually.");
    t!("Verifying your email address…");
    t!("If the process doesn't complete after a few seconds, please <input type=\"submit\" class=\"textbutton\" value=\"click here\" />.");

    t!("Manage your key on {{domain}}");

    t!("Hi,");
    t!("This is an automated message from <a href=\"{{base_uri}}\" style=\"text-decoration:none; color: #333\">{{domain}}</a>.");
    t!("If you didn't request this message, please ignore it.");
    t!("Forte key: <tt>{{primary_fp}}</tt>");
    t!("To manage and delete listed addresses on this key, please follow the link below:");
    t!("You can find more info at <a href=\"{{base_uri}}/about\">{{domain}}/about</a>.");
    t!("distributing OpenPGP keys since 2019");

    t!("Hi,");
    t!("This is an automated message from {{domain}}.");
    t!("If you didn't request this message, please ignore it.");
    t!("Forte key: {{primary_fp}}");
    t!("To manage and delete listed addresses on this key, please follow the link below:");
    t!("You can find more info at {{base_uri}}/about");
    t!("distributing OpenPGP keys since 2019");

    t!("Verify {{userid}} for your key on {{domain}}");

    t!("Hi,");
    t!("This is an automated message from <a href=\"{{base_uri}}\" style=\"text-decoration:none; color: #333\">{{domain}}</a>.");
    t!("If you didn't request this message, please ignore it.");
    t!("Forte key: <tt>{{primary_fp}}</tt>");
    t!("To let others find this key from your email address \"<a rel=\"nofollow\" href=\"#\" style=\"text-decoration:none; color: #333\">{{userid}}</a>\", please click the link below:");
    t!("You can find more info at <a href=\"{{base_uri}}/about\">{{domain}}/about</a>.");
    t!("distributing OpenPGP keys since 2019");

    t!("Hi,");
    t!("This is an automated message from {{domain}}.");
    t!("If you didn't request this message, please ignore it.");
    t!("Forte key: {{primary_fp}}");
    t!("To let others find this key from your email address \"{{userid}}\",\nplease follow the link below:");
    t!("You can find more info at {{base_uri}}/about");
    t!("distributing OpenPGP keys since 2019");
}
