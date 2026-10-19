const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const ts = require('typescript');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const output = ts.transpileModule(fs.readFileSync(__dirname + '/../src/components/screenshot.tsx', 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.React, esModuleInterop: true } }).outputText;
const moduleExports = {};
vm.runInNewContext(output, { exports: moduleExports, require });
const { screenshotText, screenshotView } = moduleExports;
const text = screenshotText([['private-machine', '服务器 1'], ['proxy.example.com', '[已隐藏]']]);

test('masks addresses including unknown connection IPs while preserving dates and clock times', () => {
  const value = text('private-machine 203.0.113.8/32 2001:db8::1 ::1 fe80::1234%eth0 proxy.example.com https://other.example/sub/secret user@example.com');
  for (const secret of ['private-machine', '203.0.113.8', '2001:db8', '::1', '1234', 'proxy.example.com', 'other.example', 'user@example.com']) assert.ok(!value.includes(secret), secret);
  assert.equal(text('2026/10/18 10:20:30'), '2026/10/18 10:20:30');
});

test('protects visible text, tooltips, forms, configuration and secret reveal components without mutating data', () => {
  const Secret = ({ value }) => React.createElement('p', null, value);
  const input = React.createElement('input', { value: 'private-machine', onChange: () => {} });
  const source = React.createElement('section', { title: 'private-machine 203.0.113.8' },
    React.createElement('strong', null, 'private-machine'), input,
    React.createElement('textarea', { value: 'some unsaved sensitive notes', readOnly: true }),
    React.createElement('pre', null, 'password: a-credential-not-in-any-list'),
    React.createElement(Secret, { value: 'revealed-credential' }));
  const protectedTree = screenshotView(source, text, new Set([Secret]));
  const html = renderToStaticMarkup(protectedTree);
  for (const value of ['private-machine', '203.0.113.8', 'some unsaved sensitive notes', 'a-credential-not-in-any-list', 'revealed-credential']) assert.ok(!html.includes(value), value);
  assert.ok(html.includes('disabled'));
  assert.equal(input.props.value, 'private-machine');
  assert.ok(renderToStaticMarkup(source).includes('private-machine'));
});

test('protects modal messages that render in child components', () => {
  const Dialog = ({ confirmation }) => React.createElement('p', null, confirmation.message);
  const source = React.createElement(Dialog, { confirmation: { title: 'Delete', message: '删除 private-machine 203.0.113.8？' } });
  const html = renderToStaticMarkup(screenshotView(source, text, new Set()));
  assert.ok(!html.includes('private-machine') && !html.includes('203.0.113.8'));
});
