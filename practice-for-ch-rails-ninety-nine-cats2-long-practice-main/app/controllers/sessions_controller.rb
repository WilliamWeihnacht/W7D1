class SessionsController < ApplicationController
  before_action :require_logged_out, except: [:destroy]

  def new
    @user = User.new
    render :new
  end

  def create
    @user = User.find_by_credentials(params[:user][:username], params[:user][:password])
    if @user
      login!(@user)
      redirect_to root_url 
    else
      render :new
    end
  end

  def destroy  
    current_user.reset_session_token! if current_user
    session[:session_token] = nil
    redirect_to new_session_url
  end


end