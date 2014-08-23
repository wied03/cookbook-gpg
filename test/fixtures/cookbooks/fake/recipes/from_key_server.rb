with 'bob' do |username|
  user_with_home(self, username)

  bsw_gpg_load_key_from_key_server 'from key server test' do
    for_user username
    key_server 'keyserver.ubuntu.com'
    key_id '561F9B9CAC40B2F7'
  end
end