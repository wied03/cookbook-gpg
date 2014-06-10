def whyrun_supported?
  true
end

use_inline_resources

def scoped(value)
  yield value
end

action :import do
  scoped '/tmp/chef_gpg_import.key' do |tmp_key_path|
    file tmp_key_path do
      content new_resource.key_contents
      owner new_resource.username
    end

    scoped "shred -n 20 -z -u #{tmp_key_path}" do |cleanup|
      # If the GPG import fails, this will ensure we still cleanup the key
      execute "gpg2 --import #{tmp_key_path} || #{cleanup}" do
        user new_resource.username
      end

      execute cleanup
    end
  end
end