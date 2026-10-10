"""Inventory declared bundle dependencies; this is not a GN target closure."""

def inventory_dependencies(bundles, root):
    components = {}
    for binding, bundle in bundles:
        component = bundle['component']
        name = component['name']
        if name in components:
            raise ValueError('Ambiguous component name: ' + name)
        deps = component.get('deps', {})
        edges = []
        for kind in ('components', 'third_party'):
            values = deps.get(kind, [])
            if not isinstance(values, list) or any(not isinstance(value, str) or not value for value in values):
                raise ValueError('Unsupported dependency declaration: ' + name)
            edges.extend(dict(name=value, kind=kind) for value in values)
        components[name] = dict(binding=binding, package_name=bundle.get('name'),
                                package_version=bundle.get('version'), dependencies=edges)
    if root not in components:
        raise ValueError('Root component is absent')
    visited, missing, edges = set(), set(), []
    pending = [root]
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        if name not in components:
            missing.add(name)
            continue
        visited.add(name)
        for dep in components[name]['dependencies']:
            edges.append(dict(source=name, target=dep['name'], kind=dep['kind']))
            pending.append(dep['name'])
    return dict(schema_version=1, experiment_kind='component_dependency_inventory',
                root_component=root, status='incomplete' if missing else 'declared_inputs_present',
                components={name: components[name] for name in sorted(visited)},
                edges=sorted(edges, key=lambda item: (item['source'], item['target'], item['kind'])),
                unresolved_components=sorted(missing), full_product_lock=False,
                build_status='not_run', compile_commands_status='not_generated',
                limitations=['Bundle-level declarations only; GN target closure and conditions are unresolved.',
                             'Package version is not a binary artifact or toolchain provenance lock.'])
