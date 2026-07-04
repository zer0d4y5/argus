# Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
#
# A Sinatra handler so semgrep's taint rules see `params` as a tainted source.
require "sinatra"

get "/vuln" do
  # PLANT: SQL injection via interpolated request param (CWE-89)
  User.where("name = '#{params[:name]}'")

  # PLANT: OS command injection via system() with request param (CWE-78)
  system("ping -c 1 #{params[:host]}")

  # PLANT: arbitrary code execution via eval of request param (CWE-95)
  eval(params[:code])

  # PLANT: insecure deserialization of request data (CWE-502)
  Marshal.load(params[:data])

  # PLANT: reflected XSS via unescaped request param in HTML (CWE-79)
  "<h1>Hello, #{params[:greeting]}</h1>"
end
