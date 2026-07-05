# Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
class UsersController < ApplicationController
  def dispatch_action
    # PLANT-GAP: dynamic method dispatch on user input via send() (CWE-470) — caught by no profile
    send(params[:action_name])
  end

  def load_class
    # PLANT(rb-unsafe-reflection, min-profile=standard, CWE-94): unsafe reflection via constantize (semgrep emits CWE-94)
    params[:type].constantize.new
  end

  def go
    # PLANT(rb-open-redirect, min-profile=standard, CWE-601): open redirect from user input
    redirect_to params[:url]
  end
end
