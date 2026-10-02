// ACE+RHG compliance gate — Jenkins shared library (v2)
//
// Usage (Jenkinsfile):
//   @Library('ace-rhg') _
//   stage('ACE Compliance Gate') {
//     steps {
//       aceGate(
//         environment:    'production',
//         failOn:         'HIGH',
//         artifactsPath:  './k8s',
//         backendPath:    './src',     // submitted for compatibility check
//         aceUrl:         env.ACE_URL,
//         notifySlack:    true
//       )
//     }
//   }

def call(Map config = [:]) {
    def environment   = config.environment ?: 'production'
    def failOn        = config.failOn ?: 'HIGH'
    def artifactsPath = config.artifactsPath ?: './k8s'
    def backendPath   = config.backendPath ?: './src'
    def aceUrl        = config.aceUrl ?: env.ACE_URL ?: 'http://localhost:8000'
    def notifySlack   = config.notifySlack ?: false

    def pipelineId = "${env.JOB_NAME}-${env.BUILD_NUMBER}"

    def artifactFiles = findFiles(glob: "${artifactsPath}/**/*.{yaml,yml,tf}")
    def backendFiles  = findFiles(glob: "${backendPath}/**/*.{py,js,ts,go}")

    def artifacts = artifactFiles.collect { f ->
        [type: inferType(f.path), name: f.path, content: base64Encode(readFile file: f.path)]
    }
    def backendSource = backendFiles.collect { f ->
        [language: inferLanguage(f.path), filename: f.path, content: base64Encode(readFile file: f.path)]
    }

    def body = [
        pipeline_id:   pipelineId,
        repo:          env.GIT_URL?.tokenize('/')?.last()?.removeSuffix('.git') ?: 'unknown/repo',
        branch:        env.GIT_BRANCH ?: 'main',
        environment:   environment,
        artifacts:     artifacts,
        backend_source: backendSource,
    ]

    def result = httpRequest(
        url: "${aceUrl}/rhg/submit",
        httpMode: 'POST',
        requestBody: writeJSON(json: body),
        contentType: 'APPLICATION_JSON',
        timeout: 120,
        consoleLogResponseBody: false,
        validResponseCodes: '200'
    )
    def parsed = readJSON(text: result.content)

    currentBuild.description = "ACE gate: ${parsed.decision}" +
        " — ${parsed.mutations_applied} auto-patches" +
        " — compat ${parsed.compatibility_verdict}"

    if (parsed.decision == 'BLOCK') {
        echo "ACE gate BLOCKED: ${parsed.blocking_findings}"
        error "ACE+RHG gate: BLOCK — ${parsed.blocking_findings.size()} unresolvable violations"
    } else {
        echo "ACE gate: ${parsed.decision}"
        echo "Report: ${parsed.report_url}"
    }
}

def inferType(filename) {
    if (filename.contains('.github/workflows')) return 'github_actions'
    if (filename.endsWith('.tf')) return 'terraform'
    if (filename.contains('Dockerfile')) return 'dockerfile'
    return 'kubernetes'
}

def inferLanguage(filename) {
    if (filename.endsWith('.py')) return 'python'
    if (filename.endsWith('.go')) return 'go'
    return 'node'
}

def base64Encode(String text) {
    return text.bytes.encodeBase64().toString()
}