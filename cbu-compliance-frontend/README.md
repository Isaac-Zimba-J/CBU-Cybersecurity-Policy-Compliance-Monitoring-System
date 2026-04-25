# CBU Compliance Monitor — Angular Frontend

## Prerequisites
- Node.js 18+: https://nodejs.org
- Angular CLI: `npm install -g @angular/cli`

## Setup
```bash
cd cbu-compliance-frontend
npm install
```

## Configure Backend URL
Edit `src/environments/environment.ts`:
```typescript
export const environment = {
  production: false,
  apiUrl: 'http://192.168.1.X:8000'   // replace with your server LAN IP
};
```

## Run (Development)
```bash
ng serve --host 0.0.0.0 --port 4200
```
- Server machine: http://localhost:4200
- Other LAN machines: http://YOUR_IP:4200

## Build (Production)
```bash
ng build
cd dist/cbu-compliance-frontend/browser
python -m http.server 4200
```

## Demo Accounts
| Role | Username | Password |
|------|----------|----------|
| Admin | admin | Admin@123 |
| Security | bwembya.rm | Bwembya@123 |
| Viewer | viewer1 | Viewer@123 |

## Full Demo (2 terminals)
Terminal 1 - Backend:
  cd cybersec_compliance && uvicorn app.main:app --host 0.0.0.0 --port 8000

Terminal 2 - Frontend:
  cd cbu-compliance-frontend && ng serve --host 0.0.0.0 --port 4200
