import { describe, it, expect, vi, beforeEach } from 'vitest';
import fs from 'fs';
import { getControlsForFinding, resetCacheForTesting } from './cccResolver.js';

vi.mock('fs');

describe('cccResolver', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    fs.existsSync.mockReturnValue(true);
    resetCacheForTesting();
  });

  it('returns empty array if finding type is not found', () => {
    fs.existsSync.mockReturnValue(true);
    fs.readFileSync.mockImplementation((path) => {
      if (path.includes('mapping.json')) return JSON.stringify({ findings: [] });
      if (path.includes('controls.json')) return JSON.stringify({ domains: [] });
    });
    
    const result = getControlsForFinding('unknown_type', null);
    expect(result).toEqual([]);
  });

  it('resolves controls based on applicability CSP', () => {
    fs.readFileSync.mockImplementation((path) => {
      if (path.includes('mapping.json')) return JSON.stringify({
        findings: [{
          finding_type: 'test_finding',
          ccc_controls_csp: ['1-1'],
          ccc_controls_cst: ['2-2']
        }]
      });
      if (path.includes('controls.json')) return JSON.stringify({
        domains: [{
          subdomains: [{
            controls: [
              { id: '1-1', text: 'CSP Control', level_mandatory: { level_1: true, level_4: true } },
              { id: '2-2', text: 'CST Control', level_mandatory: { level_1: true, level_4: true } }
            ]
          }]
        }]
      });
    });
    
    const result = getControlsForFinding('test_finding', 'CSP');
    expect(result).toEqual([{ id: '1-1', text: 'CSP Control' }]);
  });

  it('filters out controls that are not mandatory for the given level', () => {
    fs.readFileSync.mockImplementation((path) => {
      if (path.includes('mapping.json')) return JSON.stringify({
        findings: [{
          finding_type: 'test_finding',
          ccc_controls_csp: ['1-1', '1-2'],
          ccc_controls_cst: []
        }]
      });
      if (path.includes('controls.json')) return JSON.stringify({
        domains: [{
          subdomains: [{
            controls: [
              { id: '1-1', text: 'CSP Control 1', level_mandatory: { level_1: true, level_2: false } },
              { id: '1-2', text: 'CSP Control 2', level_mandatory: { level_1: true, level_2: true } }
            ]
          }]
        }]
      });
    });
    
    // Level 2 should filter out 1-1 because level_2 is false
    const result = getControlsForFinding('test_finding', 'CSP', 2);
    expect(result).toEqual([{ id: '1-2', text: 'CSP Control 2' }]);
  });

  it('resolves controls based on fallback (CST) when applicability is null', () => {
    fs.readFileSync.mockImplementation((path) => {
      if (path.includes('mapping.json')) return JSON.stringify({
        findings: [{
          finding_type: 'test_finding',
          ccc_controls_csp: ['1-1'],
          ccc_controls_cst: ['2-2']
        }]
      });
      if (path.includes('controls.json')) return JSON.stringify({
        domains: [{
          subdomains: [{
            controls: [
              { id: '1-1', text: 'CSP Control', level_mandatory: { level_1: true } },
              { id: '2-2', text: 'CST Control', level_mandatory: { level_1: true } }
            ]
          }]
        }]
      });
    });
    
    const result = getControlsForFinding('test_finding', null);
    expect(result).toEqual([{ id: '2-2', text: 'CST Control' }]);
  });
});
