import os

template_path = 'version_template.py'
output_path = 'DynamicDnsUpdater/version.py'
version = os.environ.get('PROJECT_VERSION', '1.0.0-alpha1')

with open(template_path, 'r') as template_file:
    template = template_file.read()

output = template.replace('{{VERSION}}', version)

with open(output_path, 'w') as output_file:
    output_file.write(output)
