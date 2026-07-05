# Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
#
# A Sinatra handler so semgrep's taint rules see `params` as a tainted source.
require "sinatra"

get "/vuln" do
  # PLANT(rb-sqli, min-profile=standard, CWE-89): SQL injection via interpolated request param
  User.where("name = '#{params[:name]}'")

  # PLANT-GAP: OS command injection via system() with request param (CWE-78) — semgrep reports the eval-family CWE-94 on this file instead
  system("ping -c 1 #{params[:host]}")

  # PLANT(rb-code-injection, min-profile=standard, CWE-94): arbitrary code execution via eval of request param (semgrep emits CWE-94)
  eval(params[:code])

  # PLANT(rb-deser, min-profile=standard, CWE-502): insecure deserialization of request data
  Marshal.load(params[:data])

  # PLANT(rb-xss, min-profile=standard, CWE-79): reflected XSS via unescaped request param in HTML
  "<h1>Hello, #{params[:greeting]}</h1>"
end
