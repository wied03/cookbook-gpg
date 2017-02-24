class Chef
  class Resource
    class BswGpgLoadKeyFromEncryptedDataBag < LoadKeyBaseResource
      attribute :data_bag, :kind_of => String, :required => true
      attribute :item, :kind_of => String, :required => true
      attribute :secret, :kind_of => String, :default => nil
      attribute :json_key, :kind_of => String, :required => true
    end
  end
end