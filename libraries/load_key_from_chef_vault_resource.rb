class Chef
  class Resource
    class BswGpgLoadKeyFromChefVault < LoadKeyBaseResource
      attribute :data_bag, :kind_of => String, :required => true
      attribute :item, :kind_of => String, :required => true
      attribute :json_key, :kind_of => String, :required => true
    end
  end
end