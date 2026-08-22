import fs from 'fs';
import path from 'path';

let mappingCache = null;
let controlsCache = null;

export const resetCacheForTesting = () => {
  mappingCache = null;
  controlsCache = null;
};

const loadData = () => {
  if (mappingCache && controlsCache) return;

  try {
    const getPath = (filename) => {
      const paths = [
        path.join(process.cwd(), 'ccc_integration', filename),
        path.join(process.cwd(), '..', 'ccc_integration', filename),
        `/ccc_integration/${filename}`
      ];
      return paths.find(p => fs.existsSync(p));
    };

    const mappingPath = getPath('finding_to_ccc_mapping.json');
    if (!mappingPath) throw new Error('Could not find finding_to_ccc_mapping.json');
    const mappingFile = fs.readFileSync(mappingPath, 'utf8');
    const mappingData = JSON.parse(mappingFile);
    mappingCache = {};
    for (const item of mappingData.findings || []) {
      mappingCache[item.finding_type] = item;
    }

    const controlsPath = getPath('ccc_controls.json');
    if (!controlsPath) throw new Error('Could not find ccc_controls.json');
    const controlsFile = fs.readFileSync(controlsPath, 'utf8');
    const controlsData = JSON.parse(controlsFile);
    controlsCache = {};
    for (const domain of controlsData.domains || []) {
      for (const subdomain of domain.subdomains || []) {
        for (const control of subdomain.controls || []) {
          controlsCache[control.id] = { text: control.text, level_mandatory: control.level_mandatory };
          for (const subcontrol of control.subcontrols || []) {
            controlsCache[subcontrol.id] = { text: subcontrol.text, level_mandatory: control.level_mandatory };
          }
        }
      }
    }
  } catch (error) {
    console.error('Error loading CCC data:', error);
  }
};

export const getControlsForFinding = (findingType, applicability, classificationLevel) => {
  if (!mappingCache || !controlsCache) {
    loadData();
  }

  if (!findingType || !mappingCache || !mappingCache[findingType]) {
    return [];
  }

  const findingMapping = mappingCache[findingType];

  let controlIds = [];
  if (applicability && applicability.toUpperCase() === 'CSP') {
    controlIds = findingMapping.ccc_controls_csp || [];
  } else {
    controlIds = findingMapping.ccc_controls_cst || [];
  }

  let formattedLevel = null;
  if (classificationLevel) {
    const num = classificationLevel.toString().replace(/[^0-9]/g, '');
    if (num) formattedLevel = `level_${num}`;
  }

  const results = [];
  for (const cid of controlIds) {
    const cData = controlsCache[cid];
    if (!cData) {
      results.push({ id: cid, text: 'Control text not found.' });
      continue;
    }
    
    // Filter by data_classification_level
    if (formattedLevel && cData.level_mandatory && cData.level_mandatory[formattedLevel] === false) {
      continue;
    }
    
    results.push({ id: cid, text: cData.text });
  }

  return results;
};
