#!/usr/bin/env node
/*
 * Generate the SBOM from the files that are actually in vendor/.
 *
 * Written rather than hand maintained because a hand written SBOM is a claim about the
 * software that drifts from the software. This reads the bytes on disk and hashes them, so
 * the document cannot describe a dependency that is not there or miss one that is.
 *
 * The dependency surface is two files. That is the point of vendoring: an SBOM you can
 * read in full in under a minute, rather than a transitive tree nobody audits.
 *
 *   node scripts/make_sbom.js            write sbom.cdx.json
 *   node scripts/make_sbom.js --check    verify the committed one still matches
 */
'use strict';
const fs = require('fs'), path = require('path'), crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'sbom.cdx.json');

/* Facts about each vendored library that cannot be derived from the bytes: what it is,
   who publishes it, and under what licence. Sourced from the package's own metadata, and
   the reference URL is in the document so a reader can check rather than trust. */
const KNOWN = {
  'js-yaml.min.js': {
    name: 'js-yaml',
    version: '4.1.0',
    purl: 'pkg:npm/js-yaml@4.1.0',
    licenses: ['MIT'],
    website: 'https://github.com/nodeca/js-yaml',
    source: 'https://unpkg.com/js-yaml@4.1.0/dist/js-yaml.min.js',
    why: 'YAML parsing and serialisation. Used by every surface, so the page, the CLI and '
       + 'the tests provably share one YAML implementation.',
  },
  'jszip.min.js': {
    name: 'jszip',
    version: '3.10.1',
    purl: 'pkg:npm/jszip@3.10.1',
    licenses: ['MIT', 'GPL-3.0-or-later'],
    website: 'https://github.com/Stuk/jszip',
    source: 'https://unpkg.com/jszip@3.10.1/dist/jszip.min.js',
    why: 'Builds the ZIP of patched YAML in the browser. Not used by the CLI.',
  },
};

const sha256 = (p) => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');

function build() {
  const dir = path.join(ROOT, 'vendor');
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.js')).sort();

  const unknown = files.filter((f) => !KNOWN[f]);
  if (unknown.length) {
    console.error('vendor/ contains files this generator does not know about:');
    for (const u of unknown) console.error('  ' + u);
    console.error('');
    console.error('Add them to KNOWN with their version, licence and origin, or remove');
    console.error('them. An SBOM that silently omits a dependency is worse than none.');
    process.exit(2);
  }

  const version = require(path.join(ROOT, 'acs_policies.js')).ACS_VERSION;
  const components = files.map(function (f) {
    const k = KNOWN[f];
    return {
      type: 'library',
      'bom-ref': k.purl,
      name: k.name,
      version: k.version,
      purl: k.purl,
      description: k.why,
      licenses: k.licenses.map((id) => ({ license: { id: id } })),
      externalReferences: [
        { type: 'website', url: k.website },
        { type: 'distribution', url: k.source },
      ],
      hashes: [{ alg: 'SHA-256', content: sha256(path.join(dir, f)) }],
      properties: [{ name: 'vendored:path', value: 'vendor/' + f }],
    };
  });

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      /* No timestamp. A generated file that changes on every run produces a diff on every
         run, and a diff that is always noise is a diff nobody reads. The content changes
         only when a dependency does, which is the only time anyone should look. */
      component: {
        type: 'application',
        'bom-ref': 'dj-acs-auditor',
        name: "DJ's ACS Auditor",
        version: version,
        description: 'Audit Kubernetes and OpenShift manifests against Red Hat Advanced '
                   + 'Cluster Security policy logic.',
      },
      properties: [
        { name: 'dependency:model', value: 'vendored, committed to the repository' },
        { name: 'dependency:package-manager', value: 'none at build or run time' },
        { name: 'note', value: 'Both libraries are committed to the repository and verified '
          + 'by hash in CI. Nothing is fetched at build or run time, which is why this tool '
          + 'works on a disconnected network.' },
      ],
    },
    components: components,
  };
}

const doc = build();
const text = JSON.stringify(doc, null, 2) + '\n';

if (process.argv.indexOf('--check') !== -1) {
  const have = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8') : '';
  if (have !== text) {
    console.error('sbom.cdx.json does not match vendor/ and the version in the engine.');
    console.error('Regenerate it:  node scripts/make_sbom.js');
    process.exit(1);
  }
  console.log('sbom.cdx.json matches the vendored files and the current version');
  process.exit(0);
}

fs.writeFileSync(OUT, text);
console.log('wrote ' + path.relative(ROOT, OUT) + ' describing ' + doc.components.length + ' component(s)');
