include_recipe 'bsw_gpg::default'

key_bits = cookbook_file_contents 'leo.pub', 'fake'
bsw_gpg_load_key_from_string 'some key' do
  for_user 'root'
  key_contents key_bits
end