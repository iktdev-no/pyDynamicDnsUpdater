import re




def get_domain_from_fqdn(fqdn: str) -> str | None:

    match = re.search(r'([^.]+\.[^.]+)$', fqdn)
    if match:
        return match.group(1)
    return None