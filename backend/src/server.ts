import express from 'express';
import cors from 'cors';
import multer from 'multer';
import dotenv from 'dotenv';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { exec } from 'child_process';
import fs from 'fs';
import { GoogleGenerativeAI } from '@google/generative-ai';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;

// Initialize Gemini
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || '');

const db: Record<string, { status: string, sessions: any[], error?: string }> = {};

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, '../../shared/pcaps');
    if (!fs.existsSync(dir)){
        fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});
const upload = multer({ storage });

function calculateRisk(session: any) {
  let score = 100;
  let level = 'LOW';
  
  if (!session.starttls) {
    score -= 40;
    session.findings.push('NO_STARTTLS');
  }

  if (session.tls) {
    if (session.tls.version === 'TLS 1.0' || session.tls.version === 'TLS 1.1') {
      score -= 50;
      session.findings.push('OBSOLETE_TLS_VERSION');
    }
    if (session.tls.cipher_suite && session.tls.cipher_suite.includes('3DES')) {
      score -= 30;
      session.findings.push('WEAK_CIPHER');
    }
  }

  if (score < 40) level = 'CRITICAL';
  else if (score < 70) level = 'HIGH';
  else if (score < 90) level = 'MEDIUM';

  session.riskScore = Math.max(0, score);
  session.riskLevel = level;
  return session;
}

app.post('/api/upload', upload.single('pcap'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    
    const jobId = uuidv4();
    const filePath = req.file.path;
    
    db[jobId] = { status: 'pending', sessions: [] };

    const analyzerPath = path.join(__dirname, '../../analyzer/analyzer.exe');
    
    console.log(`Executing analyzer for job ${jobId}...`);
    exec(`"${analyzerPath}" "${filePath}"`, (error, stdout, stderr) => {
      if (error) {
        console.error(`Analyzer Error: ${error.message}`);
        db[jobId] = { status: 'error', sessions: [], error: error.message };
        return;
      }
      
      try {
        const parsed = JSON.parse(stdout);
        const rawFindings = Array.isArray(parsed) ? parsed : [];
        const scoredSessions = rawFindings.map((finding: any) => {
          const scored = calculateRisk(finding);
          scored.jobId = jobId;
          return scored;
        });
        
        db[jobId] = { status: 'completed', sessions: scoredSessions };
        console.log(`Job ${jobId} completed successfully. Found ${scoredSessions.length} sessions.`);
      } catch (parseError) {
        console.error("Failed to parse analyzer output:", parseError);
        console.error("Raw output:", stdout);
        db[jobId] = { status: 'error', sessions: [], error: 'Failed to parse analyzer output' };
      }
    });

    res.json({ message: 'File uploaded and analysis started', jobId });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Upload failed' });
  }
});

app.get('/api/sessions/:jobId', (req, res) => {
  const job = db[req.params.jobId] || { status: 'not_found', sessions: [] };
  res.json(job);
});

app.post('/api/ai-explain/:jobId', async (req, res) => {
  try {
    if (!process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY === 'your_api_key_here') {
      return res.status(400).json({ error: 'GEMINI_API_KEY is not configured in backend/.env' });
    }

    const job = db[req.params.jobId];
    if (!job || !job.sessions || job.sessions.length === 0) {
       return res.status(404).json({ error: 'No sessions found for this job' });
    }

    const prompt = `
You are a senior SOC analyst and network forensics expert.
Analyze the following extracted email session cryptographic facts. 
Explain the risk posture of these sessions, and provide concrete remediation steps if any risks are found.

Sessions Data:
${JSON.stringify(job.sessions, null, 2)}

Provide your response in professional markdown format. Use bullet points and headers. Keep it concise but authoritative.
`;

    const modelsToTry = ["gemini-flash-latest", "gemini-2.5-pro", "gemini-3-flash-preview"];
    let result = null;
    let lastError = null;

    for (const modelName of modelsToTry) {
      try {
        const model = genAI.getGenerativeModel({ model: modelName });
        result = await model.generateContent(prompt);
        break; // Success! Exit the loop.
      } catch (e: any) {
        console.error(`Model ${modelName} failed:`, e.message);
        lastError = e;
      }
    }

    if (!result) {
      throw lastError;
    }
    
    res.json({ explanation: result.response.text() });
  } catch (error) {
    console.error("AI Error:", error);
    res.status(500).json({ error: 'AI Analysis failed' });
  }
});

app.listen(PORT, () => {
  console.log(`Backend listening on port ${PORT}`);
});