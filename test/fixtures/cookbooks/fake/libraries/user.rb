def user_with_home(scope,username)
  scope.user username do
    action :create
    manage_home true
    home "/home/#{username}"
  end
end
