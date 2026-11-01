package ace.api.security_test

import future.keywords.if
import future.keywords.in

import data.ace.api.security

# --- helpers ---------------------------------------------------------------

_input(routes, content) := {
	"kind": "SourceCode",
	"language": "python",
	"filename": "app.py",
	"routes": routes,
	"content": content,
	"imports": [],
}

_has_rule(findings, rule_id) if {
	# OPA encodes an object-valued partial set (``deny[finding]``) as an
	# object with boolean values, so iterate key/value to recover the finding.
	some finding, _ in findings
	finding.rule_id == rule_id
}

# A file that has auth, pagination and no dangerous structural pattern. This
# must stay clean so the policy does not add noise to every scan.
test_clean_source_has_no_findings if {
	findings := security.deny with input as _input(
		["/users"],
		`@app.get("/users")
def list_users(user=Depends(get_current_user), limit: int = 50, offset: int = 0):
    return db.query(User).limit(limit).offset(offset).all()
`,
	)
	count(findings) == 0
}

# --- API1: Broken Object Level Authorization -------------------------------

test_api1_object_route_without_ownership_check if {
	findings := security.deny with input as _input(
		["/api/users/{user_id}"],
		`@app.get("/api/users/{user_id}")
def get_user(user_id):
    return db.get(user_id)
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API1")
}

test_api1_owner_check_suppresses_finding if {
	findings := security.deny with input as _input(
		["/api/documents/{document_id}"],
		`@app.get("/api/documents/{document_id}")
def get_document(document_id):
    if owner_id == current_user.id:
        return db.get(document_id)
    raise Forbidden()
`,
	)
	count(findings) == 0
}

# --- API2: Broken Authentication -------------------------------------------

test_api2_credentials_in_query_string if {
	findings := security.deny with input as _input(
		["/login"],
		`@app.get("/login")
def login():
    password = request.args.get("password")
    return authenticate(request.args.get("username"), password)
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API2-QUERY-CREDENTIALS")
}

test_api2_session_cookie_without_flags if {
	findings := security.deny with input as _input(
		[],
		`response.set_cookie("session", token)
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API2-COOKIE-FLAGS")
}

test_api2_session_cookie_with_flags_is_clean if {
	findings := security.deny with input as _input(
		[],
		`response.set_cookie("session", token, httponly=True, secure=True, samesite="Lax")
`,
	)
	count(findings) == 0
}

# --- API3: Broken Object Property Level Authorization ----------------------

test_api3_raw_request_payload_bound_to_model if {
	findings := security.deny with input as _input(
		["/profile"],
		`@app.post("/profile")
async def update_profile():
    user = User(**await request.json())
    return user
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API3-MASS-ASSIGNMENT")
}

test_api3_node_model_create_from_raw_body if {
	findings := security.deny with input as _input(
		["/profile"],
		`router.post("/profile", async (req, res) => {
  const user = await User.create(req.body);
  res.json(user);
});
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API3-MASS-ASSIGNMENT")
}

test_api3_serializer_exposes_all_fields if {
	findings := security.deny with input as _input(
		[],
		`class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API3-EXCESSIVE-FIELDS")
}

# --- API4: Unrestricted Resource Consumption -------------------------------

test_api4_collection_without_pagination if {
	findings := security.deny with input as _input(
		["/api/users"],
		`@app.get("/api/users")
def list_users():
    return db.query(User).all()
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API4-NO-PAGINATION")
}

test_api4_upload_without_size_limit if {
	findings := security.deny with input as _input(
		["/uploads"],
		`@app.post("/uploads")
def upload():
    return save(request.files["file"])
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API4-UPLOAD-LIMIT")
}

# --- API5: Broken Function Level Authorization ----------------------------

test_api5_admin_route_without_role_guard if {
	findings := security.deny with input as _input(
		["/admin/settings"],
		`@app.get("/admin/settings")
def settings():
    return load_settings()
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API5-PRIVILEGED-ROUTE")
}

test_api5_admin_route_with_role_guard_is_clean if {
	findings := security.deny with input as _input(
		["/admin/settings"],
		`@app.get("/admin/settings")
@roles_required("admin")
def settings():
    return load_settings()
`,
	)
	count(findings) == 0
}

# --- API6: Unrestricted Access to Sensitive Business Flows ----------------

test_api6_checkout_without_rate_limit if {
	findings := security.deny with input as _input(
		["/checkout"],
		`@app.post("/checkout")
def checkout():
    return create_order(cart)
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API6-NO-ANTI-AUTOMATION")
}

test_api6_checkout_with_rate_limit_is_clean if {
	findings := security.deny with input as _input(
		["/checkout"],
		`@app.post("/checkout")
@limiter.limit("5/minute")
def checkout():
    return create_order(cart)
`,
	)
	count(findings) == 0
}

# --- API7: Server Side Request Forgery ------------------------------------

test_api7_user_controlled_outbound_url if {
	findings := security.deny with input as _input(
		["/fetch"],
		`@app.get("/fetch")
def fetch_url():
    url = request.args.get("url")
    return requests.get(url, timeout=5).text
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API7-SSRF")
}

test_api7_allowlist_suppresses_ssrf_finding if {
	findings := security.deny with input as _input(
		["/fetch"],
		`@app.get("/fetch")
def fetch_url():
    url = request.args.get("url")
    if not is_safe_url(url):
        raise Forbidden()
    return requests.get(url, timeout=5).text
`,
	)
	count(findings) == 0
}

# --- API8: Security Misconfiguration --------------------------------------

test_api8_tls_verification_disabled if {
	findings := security.deny with input as _input(
		[],
		`response = requests.get("https://api.example.com", verify=False, timeout=5)
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API8-TLS-VERIFY")
}

test_api8_wildcard_cors_origins if {
	findings := security.deny with input as _input(
		[],
		`app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API8-CORS-WILDCARD")
}

test_api8_graphql_introspection_enabled if {
	findings := security.deny with input as _input(
		[],
		`app = GraphQLApp(schema=schema, introspection=True, graphiql=True)
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API8-GRAPHQL-INTROSPECTION")
}

# --- API9: Improper Inventory Management ----------------------------------

test_api9_management_endpoint_exposed if {
	findings := security.deny with input as _input(
		["/actuator/env"],
		`@app.get("/actuator/env")
def env():
    return os.environ
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API9-MANAGEMENT-ENDPOINT")
}

test_api9_multiple_api_versions_in_one_file if {
	findings := security.deny with input as _input(
		["/v1/users", "/v2/users"],
		`limit = 50
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API9-VERSION-SPRAWL")
}

# --- API10: Unsafe Consumption of APIs ------------------------------------

test_api10_webhook_without_signature_check if {
	findings := security.deny with input as _input(
		["/webhooks/payment"],
		`@app.post("/webhooks/payment")
def payment_webhook():
    return handle(request.json())
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API10-WEBHOOK-SIGNATURE")
}

test_api10_outbound_call_without_timeout if {
	findings := security.deny with input as _input(
		[],
		`response = requests.get("https://api.example.com/rates")
`,
	)
	_has_rule(findings, "API-SEC-OWASP-API10-NO-TIMEOUT")
}

test_api10_outbound_call_with_timeout_is_clean if {
	findings := security.deny with input as _input(
		[],
		`response = requests.get("https://api.example.com/rates", timeout=5)
`,
	)
	count(findings) == 0
}
