class Chef
  class Resource
    class BswGpgLoadKeyFromString < LoadKeyBaseResource
      attribute :key_contents, :kind_of => String, :required => true
    end
  end
end