if defined?(ChefSpec)

  def replace_bsw_gpg_load_key_from_string(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:bsw_gpg_load_key_from_string, :replace, resource)
  end

  def replace_bsw_gpg_load_key_from_chef_vault(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:bsw_gpg_load_key_from_chef_vault, :replace, resource)
  end

  def replace_bsw_gpg_load_key_from_key_server(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:bsw_gpg_load_key_from_key_server, :replace, resource)
  end

  def replace_bsw_gpg_load_key_from_data_bag(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:bsw_gpg_load_key_from_data_bag, :replace, resource)
  end

  def replace_bsw_gpg_load_key_from_encrypted_data_bag(resource)
    ChefSpec::Matchers::ResourceMatcher.new(:bsw_gpg_load_key_from_encrypted_data_bag, :replace, resource)
  end

end
