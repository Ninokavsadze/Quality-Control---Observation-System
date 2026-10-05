const fs = require('fs');
const { GoogleGenAI } = require('@google/genai');
const { getSetting } = require('./db');

const DEFAULT_MODEL = 'gemini-2.5-flash';
const INLINE_LIMIT_BYTES = 15 * 1024 * 1024; // stay safely under the 20MB total request cap

function extToMime(filePath) {
  const ext = (filePath.split('.').pop() || '').toLowerCase();
  const map = {
    mp3: 'audio/mp3', mpeg: 'audio/mpeg', wav: 'audio/wav', m4a: 'audio/m4a',
    aac: 'audio/aac', ogg: 'audio/ogg', oga: 'audio/ogg', flac: 'audio/flac',
    webm: 'audio/webm', opus: 'audio/opus', aiff: 'audio/aiff',
  };
  return map[ext] || 'audio/mpeg';
}

function buildResponseSchema() {
  return {
    type: 'object',
    properties: {
      transcript: { type: 'string', description: 'აუდიოს სრული ტრანსკრიფცია ქართულ ენაზე' },
      summary: { type: 'string', description: 'ზოგადი შეჯამება ქართულ ენაზე — რა მოხდა საუბარში/დაკვირვებისას' },
      overall_comment: { type: 'string', description: 'საერთო შეფასების კომენტარი ქართულ ენაზე' },
      criteria_results: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            criterion: { type: 'string' },
            score: { type: 'number', description: 'მინიჭებული ქულა' },
            max_score: { type: 'number', description: 'მაქსიმალური შესაძლო ქულა ამ კრიტერიუმზე' },
            comment: { type: 'string', description: 'დასაბუთება ქართულ ენაზე, კონკრეტული ციტატებით საშუალებისამებრ' },
          },
          required: ['criterion', 'score', 'max_score', 'comment'],
        },
      },
    },
    required: ['transcript', 'summary', 'overall_comment', 'criteria_results'],
  };
}

function buildPrompt(criteriaItems, note) {
  const list = criteriaItems
    .map((c, i) => `${i + 1}. ${c.text} (მაქსიმალური ქულა: ${c.max_score})`)
    .join('\n');
  return `შენ ხარ ხარისხის კონტროლის ექსპერტი, რომელიც აფასებს თანამშრომლისა და მომხმარებლის საუბრის/დაკვირვების აუდიო ჩანაწერს ქართული ელექტრონიკის მაღაზიის ქსელისთვის (Zoommer).

დავალება:
1. მოამზადე აუდიოს სრული ტრანსკრიფცია ქართულ ენაზე (თუ საუბარშია სხვა ენა, თარგმნის გარეშე ჩაწერე ისე, როგორც ითქვა). ტრანსკრიფციაში ყოველი რეპლიკა დაწერე ახალ ხაზზე, სათანადო ეტიკეტით დასაწყისში — ზუსტად „თანამშრომელი: “ ან „მომხმარებელი: “ — რომ სპიკერები ერთმანეთისგან ცალსახად გამოირჩეოდეს.
2. შეაფასე თანამშრომლის საუბარი ქვემოთ მოცემული კრიტერიუმების მიხედვით. თითოეულ კრიტერიუმზე მიანიჭე ქულა 0-დან მითითებულ მაქსიმუმამდე და დაასაბუთე მოკლედ, კონკრეტული მაგალითებით საუბრიდან.
3. დაწერე ზოგადი შეჯამება და საერთო კომენტარი.

${note ? `დამატებითი კონტექსტი: ${note}\n` : ''}
შეფასების კრიტერიუმები:
${list}

უპასუხე მხოლოდ მითითებული JSON სქემის მიხედვით, ქართულ ენაზე.`;
}

// Scoring-only variant: used when the transcript is already known (e.g. recordings
// imported from an external pipeline via POST /api/import/recording) — no audio is
// sent to Gemini at all, just the transcript text, so there's no transcription step
// and no audio upload cost. Returns the same criteria_results/summary/overall_comment
// shape as evaluateRecording, minus "transcript" (the caller already has it).
function buildScoringResponseSchema() {
  const schema = buildResponseSchema();
  delete schema.properties.transcript;
  schema.required = schema.required.filter((k) => k !== 'transcript');
  return schema;
}

function buildScoringPrompt(transcript, criteriaItems, note) {
  const list = criteriaItems
    .map((c, i) => `${i + 1}. ${c.text} (მაქსიმალური ქულა: ${c.max_score})`)
    .join('\n');
  return `შენ ხარ ხარისხის კონტროლის ექსპერტი, რომელიც აფასებს თანამშრომლისა და მომხმარებლის საუბრის/დაკვირვების უკვე მზა ტრანსკრიფციას ქართული ელექტრონიკის მაღაზიის ქსელისთვის (Zoommer). ტრანსკრიფცია მოცემულია ქვემოთ — შენ არ გჭირდება მისი ხელახლა შედგენა.

დავალება:
1. შეაფასე თანამშრომლის საუბარი ქვემოთ მოცემული კრიტერიუმების მიხედვით. თითოეულ კრიტერიუმზე მიანიჭე ქულა 0-დან მითითებულ მაქსიმუმამდე და დაასაბუთე მოკლედ, კონკრეტული მაგალითებით საუბრიდან.
2. დაწერე ზოგადი შეჯამება და საერთო კომენტარი.

${note ? `დამატებითი კონტექსტი: ${note}\n` : ''}
შეფასების კრიტერიუმები:
${list}

ტრანსკრიფცია:
${transcript}

უპასუხე მხოლოდ მითითებული JSON სქემის მიხედვით, ქართულ ენაზე.`;
}

async function evaluateTranscript({ transcript, criteriaItems, note }) {
  const apiKey = (getSetting('gemini_api_key') || process.env.GEMINI_API_KEY);
  if (!apiKey) {
    const err = new Error('GEMINI_API_KEY_MISSING');
    err.code = 'GEMINI_API_KEY_MISSING';
    throw err;
  }
  const model = getSetting('gemini_model', DEFAULT_MODEL);
  const ai = new GoogleGenAI({ apiKey });

  const prompt = buildScoringPrompt(transcript, criteriaItems, note);
  const schema = buildScoringResponseSchema();

  const interaction = await ai.interactions.create({
    model,
    input: [{ type: 'text', text: prompt }],
    response_format: {
      type: 'text',
      mime_type: 'application/json',
      schema,
    },
  });

  const raw = interaction.output_text;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    const err = new Error('GEMINI_BAD_JSON: ' + raw);
    err.code = 'GEMINI_BAD_JSON';
    throw err;
  }
  parsed.transcript = transcript;
  return { parsed, raw };
}

async function evaluateRecording({ filePath, criteriaItems, note }) {
  const apiKey = (getSetting('gemini_api_key') || process.env.GEMINI_API_KEY);
  if (!apiKey) {
    const err = new Error('GEMINI_API_KEY_MISSING');
    err.code = 'GEMINI_API_KEY_MISSING';
    throw err;
  }
  const model = getSetting('gemini_model', DEFAULT_MODEL);
  const ai = new GoogleGenAI({ apiKey });
  const mimeType = extToMime(filePath);
  const stat = fs.statSync(filePath);

  let audioPart;
  if (stat.size <= INLINE_LIMIT_BYTES) {
    const data = fs.readFileSync(filePath, { encoding: 'base64' });
    audioPart = { type: 'audio', data, mime_type: mimeType };
  } else {
    const uploaded = await ai.files.upload({ file: filePath, config: { mimeType } });
    audioPart = { type: 'audio', uri: uploaded.uri, mime_type: uploaded.mimeType || mimeType };
  }

  const prompt = buildPrompt(criteriaItems, note);
  const schema = buildResponseSchema();

  const interaction = await ai.interactions.create({
    model,
    input: [
      { type: 'text', text: prompt },
      audioPart,
    ],
    response_format: {
      type: 'text',
      mime_type: 'application/json',
      schema,
    },
  });

  const raw = interaction.output_text;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    const err = new Error('GEMINI_BAD_JSON: ' + raw);
    err.code = 'GEMINI_BAD_JSON';
    throw err;
  }
  return { parsed, raw };
}

module.exports = { evaluateRecording, evaluateTranscript, DEFAULT_MODEL };
