const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const Module = require('node:module');
const path = require('node:path');

const repositoryRoot = path.resolve(__dirname, '..');
const actionFixturePath = process.env.RELEASE_PLEASE_ACTION_FIXTURE;
if (!actionFixturePath) {
  throw new Error('RELEASE_PLEASE_ACTION_FIXTURE must point to the pinned action fixture');
}

const actionVersion = require(path.join(actionFixturePath, 'package.json')).version;
assert.equal(actionVersion, '4.4.1', 'fixture must match the pinned Release Please Action version');
const packageLock = JSON.parse(fs.readFileSync(path.join(actionFixturePath, 'package-lock.json'), 'utf8'));
const releasePleaseVersion = packageLock.packages['node_modules/release-please'].version;
assert.equal(releasePleaseVersion, '17.3.0', 'fixture must match the pinned Release Please engine version');

// The action bundles Release Please into dist/index.js. Expose its internal package exports
// in memory so this fixture exercises that exact bundle without installing npm packages.
const actionBundle = fs.readFileSync(path.join(actionFixturePath, 'dist/index.js'), 'utf8');
for (const template of [
  'template.hbs',
  'template1.hbs',
  'header.hbs',
  'header1.hbs',
  'commit.hbs',
  'commit1.hbs',
  'footer.hbs',
  'footer1.hbs',
]) {
  assert(fs.existsSync(path.join(actionFixturePath, 'dist', template)), `pinned action fixture must include dist/${template}`);
}
const releasePleaseMarker = 'exports.VERSION = exports.manifestSchema = exports.configSchema = exports.GitHub';
const releasePleaseOffset = actionBundle.indexOf(releasePleaseMarker);
assert.notEqual(releasePleaseOffset, -1, 'pinned action bundle must export the Release Please API');
const moduleHeaders = [...actionBundle.slice(0, releasePleaseOffset).matchAll(/\/\*\*\*\/\s+(\d+):/g)];
assert.notEqual(moduleHeaders.length, 0, 'Release Please API module must exist in the pinned bundle');
const releasePleaseModuleId = moduleHeaders[moduleHeaders.length - 1][1];
const bundleExport = 'module.exports = __webpack_exports__;';
assert.equal(actionBundle.split(bundleExport).length - 1, 1, 'pinned bundle export point must be unique');
const exposedBundle = actionBundle.replace(
  bundleExport,
  `module.exports = {releasePlease: __nccwpck_require__(${releasePleaseModuleId})};`
);
const bundleFilename = path.join(actionFixturePath, 'dist', `fixture-${actionVersion}.cjs`);
const bundleModule = new Module(bundleFilename, module);
bundleModule.filename = bundleFilename;
bundleModule.paths = Module._nodeModulePaths(path.dirname(bundleFilename));
require.cache[bundleFilename] = bundleModule;
bundleModule._compile(exposedBundle, bundleFilename);
const {GitHub, Manifest, VERSION} = bundleModule.exports.releasePlease;
assert.equal(VERSION, releasePleaseVersion, 'action bundle and package lock must use the same engine version');
const quietLogger = {
  debug() {},
  info() {},
  warn() {},
  error() {},
};

const files = new Map([
  ['release-please-config.json', fs.readFileSync(path.join(repositoryRoot, 'release-please-config.json'), 'utf8')],
  ['.release-please-manifest.json', '{".":"0.3.0"}\n'],
  [
    'Cargo.toml',
    '[package]\nname = "baffle-proxy"\nversion = "0.3.0"\n\n' +
      '[workspace]\nmembers = ["crates/baffle-client"]\n\n' +
      '[dependencies]\nbaffle-client = { version = "0.3.0", path = "crates/baffle-client" }\n',
  ],
  [
    'crates/baffle-client/Cargo.toml',
    '[package]\nname = "baffle-client"\nversion = "0.3.0"\n',
  ],
  [
    'Cargo.lock',
    'version = 4\n\n' +
      '[[package]]\nname = "baffle-client"\nversion = "0.3.0"\n\n' +
      '[[package]]\nname = "baffle-proxy"\nversion = "0.3.0"\ndependencies = ["baffle-client"]\n',
  ],
]);
assert.deepEqual(
  Object.keys(JSON.parse(files.get('release-please-config.json')).packages),
  ['.'],
  'both Cargo crates must use the single root Release Please package'
);

const scenarios = [
  {
    name: 'client patch',
    version: '0.3.1',
    message: 'fix(client): correct response parsing',
    paths: ['crates/baffle-client/src/lib.rs'],
  },
  {
    name: 'client minor',
    version: '0.4.0',
    message: 'feat(client): add session metadata',
    paths: ['crates/baffle-client/src/lib.rs'],
  },
  {
    name: 'client-only breaking change',
    version: '1.0.0',
    message: 'feat(client)!: replace the session config format\n\nBREAKING CHANGE: session files now use schema v2.',
    paths: ['crates/baffle-client/src/lib.rs'],
  },
  {
    name: 'proxy-only breaking change',
    version: '1.0.0',
    message: 'feat(proxy)!: require explicit unmatched policy\n\nBREAKING CHANGE: unmatched requests now require a configured policy.',
    paths: ['src/lib.rs'],
  },
  {
    name: 'breaking changes in both crates',
    version: '1.0.0',
    message: 'feat!: change the shared session contract\n\nBREAKING CHANGE: both crates now use the v2 contract.',
    paths: ['src/lib.rs', 'crates/baffle-client/src/lib.rs'],
  },
];

function githubFileContents(content) {
  return {
    content: Buffer.from(content, 'utf8').toString('base64'),
    parsedContent: content,
    sha: crypto.createHash('sha1').update(content).digest('hex'),
  };
}

async function* one(value) {
  yield value;
}

async function exerciseScenario(scenario) {
  const github = await GitHub.create({
    owner: 'fixture-owner',
    repo: 'baffle',
    defaultBranch: 'main',
    token: 'fixture-token',
  });

  github.getFileContentsOnBranch = async file => {
    const normalizedPath = file.replace(/^\.\//, '');
    const content = files.get(normalizedPath);
    if (content === undefined) {
      throw Object.assign(new Error(`fixture file not found: ${file}`), {status: 404});
    }
    return githubFileContents(content);
  };

  const releasedPullRequest = {
    headBranchName: 'release-please--branches--main--components--baffle-proxy',
    baseBranchName: 'main',
    number: 1,
    title: 'chore: release 0.3.0',
    body: '',
    labels: ['autorelease: tagged'],
    files: [],
    sha: 'baseline',
  };

  github.releaseIterator = () => one({
    id: 1,
    tagName: 'v0.3.0',
    name: '0.3.0',
    sha: 'baseline',
    url: 'https://github.com/fixture-owner/baffle/releases/tag/v0.3.0',
    notes: '',
  });
  github.mergeCommitIterator = async function* () {
    yield {
      sha: `change-${scenario.name}`,
      message: scenario.message,
      files: scenario.paths,
    };
    yield {
      sha: 'baseline',
      message: 'chore: release 0.3.0',
      files: [],
      pullRequest: releasedPullRequest,
    };
  };

  const manifest = await Manifest.fromManifest(
    github,
    'main',
    'release-please-config.json',
    '.release-please-manifest.json',
    {logger: quietLogger, releaseSearchDepth: 5, commitSearchDepth: 10}
  );
  const generated = await manifest.buildPullRequests();
  assert.equal(generated.length, 1, `${scenario.name}: one combined release PR`);
  const generatedPullRequest = generated[0];
  assert.equal(
    generatedPullRequest.version.toString(),
    scenario.version,
    `${scenario.name}: Release Please selected version before candidate sync`
  );

  const updatePaths = new Set(generatedPullRequest.updates.map(update => update.path));
  for (const requiredPath of [
    'Cargo.toml',
    'crates/baffle-client/Cargo.toml',
    'Cargo.lock',
    '.release-please-manifest.json',
  ]) {
    assert(updatePaths.has(requiredPath), `${scenario.name}: missing Release Please update for ${requiredPath}`);
  }

  const updatesByPath = new Map(
    generatedPullRequest.updates.map(update => [update.path, update])
  );
  const updateContent = file => {
    const update = updatesByPath.get(file);
    assert(update, `${scenario.name}: missing update for ${file}`);
    return update.updater.updateContent(files.get(file), quietLogger);
  };
  const updatedRootCargo = updateContent('Cargo.toml');
  const updatedClientCargo = updateContent('crates/baffle-client/Cargo.toml');
  const updatedLock = updateContent('Cargo.lock');
  const updatedManifest = updateContent('.release-please-manifest.json');
  assert.match(updatedRootCargo, new RegExp(`version = "${scenario.version}"`));
  assert.match(
    updatedRootCargo,
    new RegExp(`baffle-client = \\{ version = "${scenario.version}"`)
  );
  assert.match(updatedClientCargo, new RegExp(`version = "${scenario.version}"`));
  for (const packageName of ['baffle-proxy', 'baffle-client']) {
    assert.match(
      updatedLock,
      new RegExp(`name = "${packageName}"\\nversion = "${scenario.version}"`)
    );
  }
  assert.deepEqual(JSON.parse(updatedManifest), {'.': scenario.version});

  const mergedPullRequest = {
    headBranchName: generatedPullRequest.headRefName,
    baseBranchName: 'main',
    number: 2,
    title: generatedPullRequest.title.toString(),
    body: generatedPullRequest.body.toString(),
    labels: generatedPullRequest.labels,
    files: [],
    sha: `merged-${scenario.name}`,
  };
  github.pullRequestIterator = () => one(mergedPullRequest);

  const releases = await manifest.buildReleases();
  assert.equal(releases.length, 1, `${scenario.name}: merged release PR is recognized`);
  assert.equal(
    releases[0].tag.toString(),
    `v${scenario.version}`,
    `${scenario.name}: merged PR creates the synchronized vX.Y.Z tag`
  );
  assert.equal(
    releases[0].name,
    `v${scenario.version}`,
    `${scenario.name}: release name uses the selected version`
  );
}

(async () => {
  for (const scenario of scenarios) {
    await exerciseScenario(scenario);
  }
  process.stdout.write(`Release Please 17.3.0 selected and tagged all ${scenarios.length} version fixtures.\n`);
})().catch(error => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
