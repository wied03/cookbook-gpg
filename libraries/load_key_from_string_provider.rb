class Chef
  class Provider
    class BswGpgLoadKeyFromString < BaseGpgProvider
      def initialize(new_resource, run_context)
        super
      end

      def load_current_resource
        @current_resource ||= Chef::Resource::BswGpgLoadKeyFromString.new(new_resource.name)
        @current_resource.key_contents(new_resource.key_contents)
        @current_resource.for_user(new_resource.for_user)
        @current_resource
      end

      def get_key
        @new_resource.key_contents
      end
    end
  end
end