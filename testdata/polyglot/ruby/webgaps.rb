# Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
# Web-gap class caught by an argus/curated rule the registry packs miss.
def load_config(params)
  # PLANT(ruby-yaml-load, min-profile=standard, CWE-502): YAML.load on request data (argus/curated)
  YAML.load(params[:config])
end
