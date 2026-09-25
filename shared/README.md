# PhishForensics AI - Shared Data Contract

This directory contains the central data structures that connect all modules of our pipeline.

## The Pipeline
`User Input -> Backend API -> AI Analysis -> Threat Result -> Attack DNA -> Attack Reconstruction -> Safe Simulation -> Education -> Frontend`

## How to use `types.js`

We are using **JSDoc Type Definitions** inside `types.js` so that we have a typed contract without needing a complex build step or transpiler right away. 

### For Hemanth (AI Analysis) & Yashu (Backend)
When the user submits data to the Backend, the Backend passes it to the AI. The AI Analysis module must format its final output to strictly match the `PhishForensicsResult` type defined in `types.js`. Do not create separate JSON formats.

### For Monish (Frontend / UI)
When fetching the analysis result from the API, you can typecast the JSON response to `PhishForensicsResult`. This gives you auto-completion in VS Code for all fields (like `indicators.psychological`, `reconstruction`, `education.recommendedActions`).

### For Attack Reconstruction & Safe Simulation Teams
Your modules will receive the `PhishForensicsResult` (or specific parts of it, like `dna` or `threatIntent`) to build out the `reconstruction` and `simulation` arrays.

### Extensibility
This contract is designed to handle different forms of evidence (text, URLs, emails, images). Use the `InputMetadata` section to identify what is being processed. 

*Note: Do not hardcode any test data or demo responses directly into this contract or the production pipeline. Use the `demo-data/` directory if you need mock responses for local testing.*
