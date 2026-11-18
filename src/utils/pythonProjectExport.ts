import JSZip from 'jszip';
import { getDemoDatasetAsCSV } from '../data/demoTraffic';
import appPyRaw from '../../python_project/app.py?raw';
import configPyRaw from '../../python_project/config.py?raw';
import requirementsTxtRaw from '../../python_project/requirements.txt?raw';
import readmeMdRaw from '../../python_project/README.md?raw';
import dataLoaderPyRaw from '../../python_project/modules/data_loader.py?raw';
import preprocessingPyRaw from '../../python_project/modules/preprocessing.py?raw';
import edaPyRaw from '../../python_project/modules/exploratory_analysis.py?raw';
import intrusionPyRaw from '../../python_project/modules/intrusion_detection.py?raw';
import evaluationPyRaw from '../../python_project/modules/model_evaluation.py?raw';
import alertManagerPyRaw from '../../python_project/modules/alert_manager.py?raw';
import incidentManagerPyRaw from '../../python_project/modules/incident_manager.py?raw';
import reportGeneratorPyRaw from '../../python_project/modules/report_generator.py?raw';
import testNetguardPyRaw from '../../python_project/tests/test_netguard.py?raw';
import testSqlitePyRaw from '../../python_project/tests/test_sqlite_persistence.py?raw';

/**
 * Builds and triggers download of the complete Python Streamlit project ZIP
 * using the actual verified files from /python_project/.
 */
export async function downloadPythonProjectZip(): Promise<void> {
  const zip = new JSZip();

  zip.file('app.py', appPyRaw);
  zip.file('config.py', configPyRaw);
  zip.file('requirements.txt', requirementsTxtRaw);
  zip.file('README.md', readmeMdRaw);

  const dataFolder = zip.folder('data');
  if (dataFolder) {
    dataFolder.file('sample_network_traffic.csv', getDemoDatasetAsCSV());
  }

  const dbFolder = zip.folder('database');
  if (dbFolder) {
    dbFolder.file('.gitkeep', '');
  }

  const modulesFolder = zip.folder('modules');
  if (modulesFolder) {
    modulesFolder.file('__init__.py', '');
    modulesFolder.file('data_loader.py', dataLoaderPyRaw);
    modulesFolder.file('preprocessing.py', preprocessingPyRaw);
    modulesFolder.file('exploratory_analysis.py', edaPyRaw);
    modulesFolder.file('intrusion_detection.py', intrusionPyRaw);
    modulesFolder.file('model_evaluation.py', evaluationPyRaw);
    modulesFolder.file('alert_manager.py', alertManagerPyRaw);
    modulesFolder.file('incident_manager.py', incidentManagerPyRaw);
    modulesFolder.file('report_generator.py', reportGeneratorPyRaw);
  }

  const testsFolder = zip.folder('tests');
  if (testsFolder) {
    testsFolder.file('test_netguard.py', testNetguardPyRaw);
    testsFolder.file('test_sqlite_persistence.py', testSqlitePyRaw);
  }

  const content = await zip.generateAsync({ type: 'blob' });
  const url = URL.createObjectURL(content);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'NETGUARD_AI_Python_Streamlit_Project.zip';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
