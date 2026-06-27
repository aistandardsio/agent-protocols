package personserver

import "html/template"

// successData is the data passed to the success template.
type successData struct {
	Decision string
	Icon     string
	Title    string
}

// consentTemplate is the HTML template for the consent page.
const consentTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorization Request</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .card {
            background: white;
            border-radius: 16px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            max-width: 480px;
            width: 100%;
            overflow: hidden;
        }
        .header {
            background: #1a1a2e;
            color: white;
            padding: 24px;
            text-align: center;
        }
        .header h1 { font-size: 1.5rem; margin-bottom: 8px; }
        .header p { opacity: 0.8; font-size: 0.9rem; }
        .content { padding: 24px; }
        .agent-info {
            background: #f8f9fa;
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 20px;
        }
        .agent-name { font-weight: 600; font-size: 1.1rem; color: #1a1a2e; }
        .agent-id { font-size: 0.85rem; color: #666; margin-top: 4px; }
        .section { margin-bottom: 20px; }
        .section-title {
            font-size: 0.8rem;
            font-weight: 600;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }
        .scope-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        .scope-tag {
            background: #e8f4f8;
            color: #0077b6;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
        }
        .description {
            color: #444;
            line-height: 1.6;
            font-size: 0.95rem;
        }
        .meta-info {
            display: flex;
            gap: 20px;
            color: #666;
            font-size: 0.85rem;
        }
        .meta-item { display: flex; align-items: center; gap: 6px; }
        .remember-option {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 12px 16px;
            margin-bottom: 20px;
        }
        .remember-option label {
            display: flex;
            align-items: center;
            gap: 10px;
            cursor: pointer;
            font-size: 0.9rem;
            color: #444;
        }
        .remember-option input[type="checkbox"] {
            width: 18px;
            height: 18px;
            accent-color: #667eea;
        }
        .actions {
            display: flex;
            gap: 12px;
        }
        .btn {
            flex: 1;
            padding: 14px 24px;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-approve {
            background: #22c55e;
            color: white;
        }
        .btn-approve:hover { background: #16a34a; }
        .btn-deny {
            background: #ef4444;
            color: white;
        }
        .btn-deny:hover { background: #dc2626; }
        .footer {
            text-align: center;
            padding: 16px 24px;
            background: #f8f9fa;
            font-size: 0.8rem;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <h1>Authorization Request</h1>
            <p>An agent is requesting permission to act on your behalf</p>
        </div>
        <div class="content">
            <div class="agent-info">
                <div class="agent-name">{{.AgentName}}</div>
                <div class="agent-id">Agent ID: {{.AgentID}}</div>
            </div>

            <div class="section">
                <div class="section-title">Requested Permissions</div>
                <div class="scope-list">
                    {{range .Scopes}}
                    <span class="scope-tag">{{.}}</span>
                    {{end}}
                </div>
            </div>

            {{if .Description}}
            <div class="section">
                <div class="section-title">Description</div>
                <p class="description">{{.Description}}</p>
            </div>
            {{end}}

            <div class="section">
                <div class="meta-info">
                    <div class="meta-item">
                        <span>Duration:</span>
                        <strong>{{.Duration}}</strong>
                    </div>
                    <div class="meta-item">
                        <span>Acting as:</span>
                        <strong>{{.UserName}}</strong>
                    </div>
                </div>
            </div>

            <form method="POST">
                <div class="remember-option">
                    <label>
                        <input type="checkbox" name="remember">
                        Remember this decision for future requests
                    </label>
                </div>

                <div class="actions">
                    <button type="submit" name="decision" value="deny" class="btn btn-deny">Deny</button>
                    <button type="submit" name="decision" value="approve" class="btn btn-approve">Approve</button>
                </div>
            </form>
        </div>
        <div class="footer">
            AAuth Protocol &bull; Mission ID: {{.MissionID}}
        </div>
    </div>
</body>
</html>`

// successTmpl is the HTML template for the success/completion page.
var successTmpl = template.Must(template.New("success").Parse(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .card {
            background: white;
            border-radius: 16px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            max-width: 400px;
            width: 100%;
            padding: 48px;
            text-align: center;
        }
        .icon {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px;
            font-size: 2.5rem;
        }
        .icon-approve { background: #dcfce7; color: #22c55e; }
        .icon-deny { background: #fee2e2; color: #ef4444; }
        h1 { font-size: 1.75rem; color: #1a1a2e; margin-bottom: 12px; }
        p { color: #666; line-height: 1.6; }
        .note {
            margin-top: 24px;
            padding: 16px;
            background: #f8f9fa;
            border-radius: 8px;
            font-size: 0.9rem;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon icon-{{.Decision}}">{{.Icon}}</div>
        <h1>Request {{.Title}}</h1>
        <p>
            {{if eq .Decision "approve"}}
            The agent has been authorized to act on your behalf.
            {{else}}
            The authorization request has been denied.
            {{end}}
        </p>
        <div class="note">
            You can close this window now.
        </div>
    </div>
</body>
</html>`))
