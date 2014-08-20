class Chef
  class Resource
    class BswGpgLoadKeyFromKeyServer < LoadKeyBaseResource
      attribute :key_server, :kind_of => String, :required => true
      attribute :key_id, :kind_of => String, :required => true
    end
  end
end