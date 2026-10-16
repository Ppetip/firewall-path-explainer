"""Simulate ordered first-match firewall rules for supplied packets and explain redundant or shadowed rules."""
import ipaddress

def network(rule):
    return ipaddress.ip_network(rule.get('source','0.0.0.0/0'), strict=False)

def ports(rule):
    p = rule.get('ports',[0,65535])
    if isinstance(p,int):
        p = [p,p]
    if len(p)!=2 or not 0 <= p[0] <= p[1] <= 65535:
        raise ValueError('invalid port range')
    return p

def analyze(data):
    rules = data['rules']
    for rule in rules:
        network(rule); ports(rule)
        if rule['action'] not in ('allow','deny'):
            raise ValueError('invalid action')
    findings = []
    for i,rule in enumerate(rules):
        for j,prior in enumerate(rules[:i]):
            net,old = network(rule),network(prior)
            lo,hi = ports(rule); a,b = ports(prior)
            if net.version == old.version and net.subnet_of(old) and a<=lo<=hi<=b and prior.get('protocol','any') in ('any',rule.get('protocol','any')):
                findings.append(dict(kind='shadowed',rule=i,by=j)); break
    for packet in data.get('packets',[]):
        address = ipaddress.ip_address(packet['source'])
        port = int(packet['port'])
        if not 0<=port<=65535:
            raise ValueError('invalid packet port')
        matched = None
        for i,rule in enumerate(rules):
            net = network(rule); lo,hi = ports(rule)
            if address.version==net.version and address in net and lo<=port<=hi and rule.get('protocol','any') in ('any',packet['protocol']):
                matched=i; break
        findings.append(dict(kind='decision',action=rules[matched]['action'] if matched is not None else 'deny',rule=matched,packet=packet))
    return findings


def main():
    import argparse, json, sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='path to JSON input, or - for stdin')
    args = parser.parse_args()
    try:
        if args.input == '-':
            data = json.load(sys.stdin)
        else:
            with open(args.input, encoding='utf-8') as stream:
                data = json.load(stream)
        result = analyze(data)
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (ValueError, KeyError, TypeError, OSError, OverflowError) as error:
        print('Invalid input: '+str(error), file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
