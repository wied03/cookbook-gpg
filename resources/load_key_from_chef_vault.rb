actions :replace
default_action :replace

attribute :for_user, :kind_of => String, :required => true
attribute :data_bag, :kind_of => String, :required => true
attribute :item, :kind_of => String, :required => true
attribute :json_key, :kind_of => String, :required => true
