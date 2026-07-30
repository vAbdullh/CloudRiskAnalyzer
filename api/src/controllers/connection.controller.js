import crypto from 'crypto';

// In-memory mock connection store
let mockConnections = [
  {
    id: "e0a6d091-628d-4e94-8742-fa32c4e20790",
    user_id: "e23b4cad-deab-44fe-b15b-b459551c92ce",
    name: "My AWS Development Account",
    provider: "aws",
    credentials: { role_arn: "arn:aws:iam::123456789012:role/ScannerRole" },
    created_at: new Date().toISOString(),
  },
  {
    id: "f83a54b3-c5dc-4137-b769-cfad4f568a0a",
    user_id: "7effdd70-eb9d-4d97-b3ea-0a26de7f649a",
    name: "GCP Production Scan Connection",
    provider: "gcp",
    credentials: { project_id: "my-gcp-prod-project" },
    created_at: new Date().toISOString(),
  }
];

export const getConnections = async (req, res) => {
  const userId = req.user?.sub;
  const userConnections = mockConnections.filter(c => c.user_id === userId);
  res.json(userConnections);
};

export const getConnectionById = async (req, res) => {
  const { id } = req.params;
  const userId = req.user?.sub;
  const connection = mockConnections.find(c => c.id === id && c.user_id === userId);
  
  if (!connection) {
    return res.status(404).json({ error: 'Connection not found or access denied' });
  }
  res.json(connection);
};

export const createConnection = async (req, res) => {
  const { name, provider, credentials } = req.body;
  const userId = req.user?.sub;

  if (!name || !provider || !credentials) {
    return res.status(400).json({ error: 'Missing required fields: name, provider, credentials' });
  }

  const newConnection = {
    id: crypto.randomUUID(),
    user_id: userId,
    name,
    provider,
    credentials,
    created_at: new Date().toISOString(),
  };

  mockConnections.push(newConnection);
  res.status(201).json(newConnection);
};

export const updateConnection = async (req, res) => {
  const { id } = req.params;
  const { name, provider, credentials } = req.body;
  const userId = req.user?.sub;

  const index = mockConnections.findIndex(c => c.id === id && c.user_id === userId);
  if (index === -1) {
    return res.status(404).json({ error: 'Connection not found or access denied' });
  }

  if (name !== undefined) mockConnections[index].name = name;
  if (provider !== undefined) mockConnections[index].provider = provider;
  if (credentials !== undefined) mockConnections[index].credentials = credentials;

  res.json(mockConnections[index]);
};

export const deleteConnection = async (req, res) => {
  const { id } = req.params;
  const userId = req.user?.sub;

  const index = mockConnections.findIndex(c => c.id === id && c.user_id === userId);
  if (index === -1) {
    return res.status(404).json({ error: 'Connection not found or access denied' });
  }

  mockConnections.splice(index, 1);
  res.json({ message: 'Connection deleted successfully' });
};

export const getPublicInfo = (req, res) => {
  res.json({
    message: 'This is a public, unauthenticated endpoint listing supported cloud providers.',
    supported_providers: ['aws', 'gcp', 'oci'],
    version: '1.0.0'
  });
};
