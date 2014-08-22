gpg Cookbook
============
LWRP focused cookbook that helps load public or private keys into your GPG keyring from either a string, a cookbook file, or a Chef vault item.  The cookbook will check to see if the key fingerprint and user name already exist in the key ring before converging.  The resources automatically choose secret vs. public keyrings based on the header of the base64 key contents.


Requirements
------------

Ubuntu 14.04

Attributes
----------
None, LWRP focused

Usage
-----

Include the bsw_gpg::default recipe in your cookbook, which will install the gnupg2 package

#### Install from a string

```ruby
bsw_gpg_load_key_from_string 'a string key' do
    key_contents '-----BEGIN PGP PUBLIC KEY BLOCK----- (rest of key here'
    for_user 'joe' # The user you want to install the key to
end
```

#### Install from a cookbook file

```ruby
public_key_in_base_64 = cookbook_file_contents 'something.pub','mycookbookname'
bsw_gpg_load_key_from_string 'a cookbook key' do
    key_contents public_key_in_base_64
    for_user 'joe' # The user you want to install the key to
end
```

#### Install from a Chef vault item

```ruby
bsw_gpg_load_key_from_chef_vault 'a chef vault key' do
    data_bag 'thedatabag'
    item 'the_item'
    json_key 'json_key' # Expects to find a hash key with the base64 key contents in it            
    for_user 'joe' # The user you want to install the key to
end
```

#### Install from a key server

```ruby
bsw_gpg_load_key_from_key_server 'some key' do
  key_server 'keyserver.ubuntu.com'
  key_id '561F9B9CAC40B2F7'
  for_user 'root'
end
```

#### Use a non-default keyring

You can use this on any of the resources

```ruby
bsw_gpg_load_key_from_key_server 'some key' do
  key_server 'keyserver.ubuntu.com'
  key_id '561F9B9CAC40B2F7'
  for_user 'root'
  keyring_file 'stuff_secret.gpg'
end
```

#### Force the trust-db rebuild

You can use this on any of the resources.  By default, the LWRP lets gpg2 update the trustdb whenever it's executing commands on the default keyring.  When it's a custom keyring, in order to avoid gpg2 complaining about not being able to find keys you trust, the LWRP will add --no-auto-check-trustdb.  If you want to override this behavior, you can do so like below

```ruby
# TrustDB check would normally be disabled
bsw_gpg_load_key_from_key_server 'some key' do
  key_server 'keyserver.ubuntu.com'
  key_id '561F9B9CAC40B2F7'
  for_user 'root'
  keyring_file 'stuff.gpg'
  disable_trust_db_check false
end
# TrustDB check would normally be enabled
bsw_gpg_load_key_from_key_server 'some key' do
  key_server 'keyserver.ubuntu.com'
  key_id '561F9B9CAC40B2F7'
  for_user 'root'
  disable_trust_db_check true
end
```

#### Force trusting (or not) of newly imported keys

By default, after importing the key, if a private key is being imported into the default keyring, these LWRPs runs the equivalent of echo "<keyFingerprint>:6:\n" | gpg2 --import-ownertrust.  If you wish to force the trust to be imported (or not imported) regardless of the default, you can do something like this.

```ruby
# Example 1
bsw_gpg_load_key_from_chef_vault 'a chef vault key' do
    data_bag 'thedatabag'
    item 'the_item'
    json_key 'json_key' # Expects to find a hash key with the base64 key contents in it            
    for_user 'joe' # The user you want to install the key to
    force_import_owner_trust false # Will prevent an import that otherwise would have occurred
end
# Example 1
bsw_gpg_load_key_from_chef_vault 'a chef vault key' do
  data_bag 'thedatabag'
  item 'the_item'
  json_key 'json_key' # Expects to find a hash key with the base64 key contents in it            
  for_user 'joe' # The user you want to install the key to
  keyring_file 'stuff_secret.gpg'
  force_import_owner_trust true # Will force an import that otherwise would NOT have occurred  
end
```

Contributing
------------

1. Fork the repository on Github
2. Create a named feature branch (like `add_component_x`)
3. Write your change
4. Write tests for your change (if applicable)
5. Run the tests, ensuring they all pass
6. Submit a Pull Request using Github

License and Authors
-------------------
Authors: Brady Wied

Copyright (c) 2014, BSW Technology Consulting LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
