# Safe-code plants for the FP measurement eval.
def safe_load(params)
  # PLANT-FP(ruby-safe-yaml, CWE-502): safe_load forbids arbitrary objects.
  YAML.safe_load(params[:config])
end
