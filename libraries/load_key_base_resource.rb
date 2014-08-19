class Chef
  class Resource
    class LoadKeyBaseResource < Chef::Resource
      def initialize(name, run_context=nil)
        super
        @action = :replace
        @allowed_actions = [:replace]
      end

      def for_user(arg=nil)
        set_or_return(:for_user, arg, :kind_of => String, :required => true)
      end
    end
  end
end