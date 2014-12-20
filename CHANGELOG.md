gpg CHANGELOG
=============

This file is used to list changes made in each version of the gpg cookbook.

0.2.3
-----
- [Brady] - RSpec3 updates
- [intoximeter] - ChefSpec matchers and updated metadata compatibility

0.2.2
-----
- [Brady] - Handle multiple key UIDs (thanks to http://github.com/bkw for pointing this out)

0.2.1
-----
- [Brady] - README syntax fix

0.2.0
-----
- [Brady] - It doesn't make sense to allow importing private keys into non default keyrings without requiring a public keyring path as well, so modified the LWRPs to have 2 different keyring_file parameters (see README).

0.1.6
-----
- [Brady] - Handle output that changed with gnupg 2.0.26

- - -
Check the [Markdown Syntax Guide](http://daringfireball.net/projects/markdown/syntax) for help with Markdown.

The [Github Flavored Markdown page](http://github.github.com/github-flavored-markdown/) describes the differences between markdown on github and standard markdown.
