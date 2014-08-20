# Encoding: utf-8
#
# Cookbook Name:: gpg
# Recipe:: default
#
# Copyright 2014, YOUR_COMPANY_NAME
#
package 'gnupg2'
# Needed for key server operations
chef_gem 'mail-gpg' do
  version '0.2.1'
end
require 'hkp'