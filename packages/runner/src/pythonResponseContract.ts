import { spawnSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import type { ActionableChangeEvent } from '@automated-api/contracts'
import { resolveExistingPathInsideRepository } from '@automated-api/remediation'

interface PythonResponseContract {
  method: string
  resultType: string
  requiredAttributes: string[]
  itemType?: string
  enforcement?: {
    requiredAttributes: true
    sourcePath: string
    repositoryBinding: string
  }
  serialization?: {
    method: 'model_dump'
    mode: 'json'
    consumer: 'json.dump'
    required?: true
  }
}

interface PythonRepositoryCallContract {
  kind: 'langroid-firecrawl-options-v1'
  sourcePath: string
  repositoryBinding: string
  className: 'FirecrawlCrawler'
  functionName: 'crawl'
  clientType: string
  clientVariable: 'app'
  mappingName: string
  requiredMappingEntry: { key: string; value: string }
  requiredExpansionMethods: string[]
  forbiddenClientKeywords: string[]
}

const reviewedLangroidEvidenceHashes = Object.freeze([
  'e17c699015e7d634e2dd275c8895c5743f3ab3c47f8a9e99b1437ece883c5ec9',
  'be06bd136e4fab3e2ddc36485e284d4e89affc2a3dd4315909b856551ce2d772',
  '40142f9dc8b291ab0573ed9ff62732e07ba5264074fcc633bb752d9510e8321e',
  'd824fa21e0db37110105e60fff3025cd37b801063d66211a65f7ba593a85eb35',
])

const analyzer = [
  'import ast,json,sys',
  'request=json.load(sys.stdin)',
  'method_types={item["method"]:item["resultType"] for item in request["contracts"]}',
  'item_types={item["resultType"]:item["itemType"] for item in request["contracts"] if item.get("itemType")}',
  'serializers={item["resultType"]:item["serialization"] for item in request["contracts"] if item.get("serialization")}',
  'required={name:set(values) for name,values in request["requiredAccesses"].items()}',
  'required_serializers=set(request["requiredSerializers"])',
  'call_contract=request.get("callContract")',
  'model_types=set(method_types.values())|set(item_types.values())|{"DocumentMetadata"}',
  'client_names=set(request["clientTypes"])',
  'diagnostics=[];accessed={};serialized_consumed=set()',
  'def annotation_name(node):',
  ' if isinstance(node,ast.Name): return node.id',
  ' if isinstance(node,ast.Constant) and isinstance(node.value,str): return node.value.strip("\\\'\\\"").split(".")[-1]',
  ' return None',
  'class Check(ast.NodeVisitor):',
  ' def __init__(self): self.scopes=[{}];self.imported=set();self.json_modules=set();self.json_dumps=set()',
  ' def lookup(self,name):',
  '  for scope in reversed(self.scopes):',
  '   if name in scope:return scope[name]',
  '  return None',
  ' def bind(self,target,value):',
  '  if isinstance(target,ast.Name) and value:self.scopes[-1][target.id]=value',
  ' def infer(self,node):',
  '  if isinstance(node,ast.Name):return self.lookup(node.id)',
  '  if isinstance(node,ast.Call):',
  '   if isinstance(node.func,ast.Name) and node.func.id in self.imported:return "client:"+node.func.id',
  '   if isinstance(node.func,ast.Attribute):',
  '    receiver=self.infer(node.func.value)',
  '    if receiver and receiver.startswith("client:") and node.func.attr in method_types:return method_types[node.func.attr]',
  '    if receiver in serializers and node.func.attr==serializers[receiver]["method"]:',
  '     keywords={item.arg:item.value for item in node.keywords if item.arg}',
  '     mode=keywords.get("mode")',
  '     valid=isinstance(mode,ast.Constant) and mode.value==serializers[receiver]["mode"]',
  '     if not valid:diagnostics.append((node.lineno,node.col_offset+1,f"{receiver}.{node.func.attr} must use mode=\\"json\\""))',
  '     return "serialized:"+receiver if valid else None',
  '  if isinstance(node,ast.Attribute):',
  '   receiver=self.infer(node.value)',
  '   if receiver=="Document" and node.attr=="metadata":return "DocumentMetadata"',
  '   if receiver in item_types and node.attr=="data":return "list:"+item_types[receiver]',
  '  if isinstance(node,ast.Subscript):',
  '   receiver=self.infer(node.value)',
  '   if receiver and receiver.startswith("list:"):return receiver[5:]',
  '  return None',
  ' def visit_Import(self,node):',
  '  for item in node.names:',
  '   if item.name=="json":self.json_modules.add(item.asname or item.name)',
  ' def visit_ImportFrom(self,node):',
  '  if (node.module or "").split(".")[0]=="firecrawl":',
  '   for item in node.names:',
  '    if item.name in client_names:self.imported.add(item.asname or item.name)',
  '  if node.module=="json":',
  '   for item in node.names:',
  '    if item.name=="dump":self.json_dumps.add(item.asname or item.name)',
  ' def visit_FunctionDef(self,node):',
  '  self.scopes.append({})',
  '  for arg in list(node.args.posonlyargs)+list(node.args.args)+list(node.args.kwonlyargs):',
  '   name=annotation_name(arg.annotation)',
  '   if name in client_names:self.scopes[-1][arg.arg]="client:"+name',
  '  for item in node.body:self.visit(item)',
  '  self.scopes.pop()',
  ' visit_AsyncFunctionDef=visit_FunctionDef',
  ' def visit_Assign(self,node):',
  '  value=self.infer(node.value)',
  '  for target in node.targets:self.bind(target,value)',
  '  self.generic_visit(node)',
  ' def visit_AnnAssign(self,node):',
  '  self.bind(node.target,self.infer(node.value) if node.value else None);self.generic_visit(node)',
  ' def visit_For(self,node):',
  '  value=self.infer(node.iter)',
  '  self.bind(node.target,value[5:] if value and value.startswith("list:") else None)',
  '  self.generic_visit(node)',
  ' visit_AsyncFor=visit_For',
  ' def visit_comp(self,node,values):',
  '  self.scopes.append({})',
  '  for generator in node.generators:',
  '   self.visit(generator.iter);value=self.infer(generator.iter)',
  '   self.bind(generator.target,value[5:] if value and value.startswith("list:") else None)',
  '   for condition in generator.ifs:self.visit(condition)',
  '  for value in values:self.visit(value)',
  '  self.scopes.pop()',
  ' def visit_ListComp(self,node):self.visit_comp(node,[node.elt])',
  ' def visit_SetComp(self,node):self.visit_comp(node,[node.elt])',
  ' def visit_GeneratorExp(self,node):self.visit_comp(node,[node.elt])',
  ' def visit_DictComp(self,node):self.visit_comp(node,[node.key,node.value])',
  ' def visit_Attribute(self,node):',
  '  value=self.infer(node.value)',
  '  if value in model_types:accessed.setdefault(value,set()).add(node.attr)',
  '  self.generic_visit(node)',
  ' def visit_Subscript(self,node):',
  '  value=self.infer(node.value)',
  '  if value in model_types:diagnostics.append((node.lineno,node.col_offset+1,f"typed {value} response must use attribute access, not subscripting"))',
  '  self.generic_visit(node)',
  ' def visit_Call(self,node):',
  '  if isinstance(node.func,ast.Attribute):',
  '   value=self.infer(node.func.value)',
  '   if node.func.attr=="get" and value in model_types:diagnostics.append((node.lineno,node.col_offset+1,f"typed {value} response must use attributes, not .get"))',
  '   if value in serializers and node.func.attr==serializers[value]["method"]:self.infer(node)',
  '  json_dump=(isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id in self.json_modules and node.func.attr=="dump") or (isinstance(node.func,ast.Name) and node.func.id in self.json_dumps)',
  '  if json_dump and node.args:',
  '   value=self.infer(node.args[0])',
  '   if value in serializers:diagnostics.append((node.lineno,node.col_offset+1,f"typed {value} must be converted with {serializers[value][\"method\"]} before json.dump"))',
  '   if value and value.startswith("serialized:"):serialized_consumed.add(value[11:])',
  '  self.generic_visit(node)',
  'tree=ast.parse(request["content"],filename=request["path"]);check=Check();check.visit(tree)',
  'for result_type,attributes in required.items():',
  ' missing=sorted(attributes-accessed.get(result_type,set()))',
  ' if missing:diagnostics.append((1,1,f"typed {result_type} response lacks required attribute handling: {\", \".join(missing)}"))',
  'for result_type in sorted(required_serializers-serialized_consumed):',
  ' diagnostics.append((1,1,f"typed {result_type} response lacks required model_dump(mode=\\"json\\") to json.dump persistence"))',
  'def is_timeout_target(node,contract):',
  ' return isinstance(node,ast.Subscript) and isinstance(node.value,ast.Name) and node.value.id==contract["mappingName"] and isinstance(node.slice,ast.Constant) and node.slice.value==contract["requiredMappingEntry"]["key"]',
  'def binds_name(target,name):',
  ' if isinstance(target,ast.Name):return target.id==name',
  ' if isinstance(target,(ast.Tuple,ast.List)):return any(binds_name(item,name) for item in target.elts)',
  ' if isinstance(target,ast.Starred):return binds_name(target.value,name)',
  ' return False',
  'def binding_targets(node):',
  ' if isinstance(node,ast.Assign):return node.targets',
  ' if isinstance(node,(ast.AnnAssign,ast.AugAssign,ast.NamedExpr,ast.For,ast.AsyncFor)):return [node.target]',
  ' if isinstance(node,(ast.With,ast.AsyncWith)):return [item.optional_vars for item in node.items if item.optional_vars]',
  ' if isinstance(node,ast.comprehension):return [node.target]',
  ' return []',
  'def node_binds_name(node,name):',
  ' if any(binds_name(target,name) for target in binding_targets(node)):return True',
  ' if isinstance(node,ast.ExceptHandler):return node.name==name',
  ' if isinstance(node,(ast.MatchAs,ast.MatchStar)):return node.name==name',
  ' if isinstance(node,ast.MatchMapping):return node.rest==name',
  ' return False',
  'def scoped_nodes(root):',
  ' result=[];parents={};nested=[]',
  ' def visit(node):',
  '  for child in ast.iter_child_nodes(node):',
  '   if isinstance(child,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda)):nested.append(child);continue',
  '   parents[child]=node;result.append(child);visit(child)',
  ' visit(root);return result,parents,nested',
  'def is_under(node,ancestor,parents):',
  ' current=node',
  ' while current in parents:',
  '  current=parents[current]',
  '  if current is ancestor:return True',
  ' return False',
  'def check_repository_calls(tree,contract):',
  ' classes=[node for node in ast.walk(tree) if isinstance(node,ast.ClassDef) and node.name==contract["className"]]',
  ' functions=[] if len(classes)!=1 else [node for node in classes[0].body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name==contract["functionName"]]',
  ' if len(classes)!=1 or len(functions)!=1:',
  '  diagnostics.append((1,1,f"repository call contract requires exactly one {contract[\"functionName\"]} function"));return',
  ' function=functions[0];nodes,parents,nested=scoped_nodes(function)',
  ' if nested:diagnostics.append((nested[0].lineno,nested[0].col_offset+1,"repository crawl method must not introduce nested functions, lambdas, or classes"))',
  ' direct=set(function.body)',
  ' params_bindings=[node for node in nodes if node_binds_name(node,contract["mappingName"])]',
  ' params_assigns=[node for node in params_bindings if node in direct and isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id==contract["mappingName"]]',
  ' if len(params_bindings)!=1 or len(params_assigns)!=1 or ast.unparse(params_assigns[0].value)!="self.config.params.copy()":',
  '  diagnostics.append((function.lineno,function.col_offset+1,f"repository options must retain one {contract[\"mappingName\"]} = self.config.params.copy() initialization"))',
  ' timeout_writes=[]',
  ' for node in nodes:',
  '  targets=[]',
  '  if isinstance(node,ast.Assign):targets=node.targets',
  '  elif isinstance(node,(ast.AnnAssign,ast.AugAssign)):targets=[node.target]',
  '  elif isinstance(node,ast.Delete):targets=node.targets',
  '  if any(is_timeout_target(target,contract) for target in targets):timeout_writes.append(node)',
  ' guards=[]',
  ' for node in function.body:',
  '  if not isinstance(node,ast.If) or node.orelse or ast.unparse(node.test)!="self.config.timeout is not None":continue',
  '  exact=[item for item in node.body if isinstance(item,ast.Assign) and any(is_timeout_target(target,contract) for target in item.targets) and ast.unparse(item.value)==contract["requiredMappingEntry"]["value"]]',
  '  if len(exact)==1:guards.append((node,exact[0]))',
  ' if len(timeout_writes)!=1 or len(guards)!=1 or timeout_writes[0] is not guards[0][1]:',
  '  diagnostics.append((function.lineno,function.col_offset+1,f"repository options must preserve the guarded {contract[\"mappingName\"]}[{contract[\"requiredMappingEntry\"][\"key\"]!r}] = {contract[\"requiredMappingEntry\"][\"value\"]} assignment"))',
  ' mutators={"clear","pop","popitem","setdefault","update","__delitem__","__setitem__"}',
  ' for node in nodes:',
  '  if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id==contract["mappingName"] and node.func.attr in mutators:',
  '   diagnostics.append((node.lineno,node.col_offset+1,f"repository options mapping must not be mutated with {node.func.attr}"))',
  ' app_bindings=[node for node in nodes if node_binds_name(node,contract["clientVariable"])]',
  ' app_assigns=[node for node in app_bindings if node in direct and isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id==contract["clientVariable"] and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and node.value.func.id==contract["clientType"]]',
  ' constructors=[node for node in nodes if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id==contract["clientType"]]',
  ' exact_constructor=len(app_bindings)==1 and len(app_assigns)==1 and len(constructors)==1 and constructors[0] is app_assigns[0].value and not constructors[0].args and len(constructors[0].keywords)==1 and constructors[0].keywords[0].arg=="api_key" and ast.unparse(constructors[0].keywords[0].value)=="self.config.api_key"',
  ' if not exact_constructor:diagnostics.append((function.lineno,function.col_offset+1,f"repository client variable {contract[\"clientVariable\"]} must retain exact {contract[\"clientType\"]}(api_key=self.config.api_key) construction"))',
  ' mode_scrape=[node for node in function.body if isinstance(node,ast.If) and ast.unparse(node.test)=="self.config.mode == \'scrape\'"]',
  ' mode_crawl=[] if len(mode_scrape)!=1 or len(mode_scrape[0].orelse)!=1 or not isinstance(mode_scrape[0].orelse[0],ast.If) else [mode_scrape[0].orelse[0]]',
  ' if len(mode_crawl)!=1 or ast.unparse(mode_crawl[0].test)!="self.config.mode == \'crawl\'":diagnostics.append((function.lineno,function.col_offset+1,"repository call contract requires the original scrape/crawl mode branches"))',
  ' method_calls={method:[] for method in contract["requiredExpansionMethods"]}',
  ' for node in nodes:',
  '  if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id==contract["clientVariable"] and node.func.attr in method_calls:method_calls[node.func.attr].append(node)',
  ' method_attributes=[node for node in nodes if isinstance(node,ast.Attribute) and isinstance(node.value,ast.Name) and node.value.id==contract["clientVariable"] and node.attr in method_calls]',
  ' for attribute in method_attributes:',
  '  parent=parents.get(attribute)',
  '  if not isinstance(parent,ast.Call) or parent.func is not attribute:diagnostics.append((attribute.lineno,attribute.col_offset+1,f"repository SDK method {attribute.attr} must not be aliased"))',
  ' guard_line=guards[0][0].lineno if len(guards)==1 else None',
  ' params_line=params_assigns[0].lineno if len(params_assigns)==1 else None',
  ' app_line=app_assigns[0].lineno if len(app_assigns)==1 else None',
  ' for method,calls in method_calls.items():',
  '  if len(calls)!=1:diagnostics.append((function.lineno,function.col_offset+1,f"repository call contract requires exactly one app.{method} call"));continue',
  '  call=calls[0];starred=[keyword for keyword in call.keywords if keyword.arg is None];expanded=[keyword for keyword in starred if isinstance(keyword.value,ast.Name) and keyword.value.id==contract["mappingName"]]',
  '  if len(starred)!=1 or len(expanded)!=1 or any(keyword.arg in {contract["mappingName"],"timeout"} for keyword in call.keywords):diagnostics.append((call.lineno,call.col_offset+1,f"{method} must preserve repository options only through **{contract[\"mappingName\"]}"))',
  '  if app_line is None or params_line is None or guard_line is None or not (app_line<params_line<guard_line<call.lineno):diagnostics.append((call.lineno,call.col_offset+1,f"{method} must run after guarded repository timeout setup"))',
  '  assignment=parents.get(call)',
  '  if not isinstance(assignment,ast.Assign) or len(assignment.targets)!=1:diagnostics.append((call.lineno,call.col_offset+1,f"repository {method} result must retain its direct assignment"));continue',
  '  if method=="scrape":',
  '   try_node=parents.get(assignment);for_node=parents.get(try_node) if isinstance(try_node,ast.Try) else None;if_node=parents.get(for_node) if isinstance(for_node,ast.For) else None',
  '   exact_branch=len(mode_scrape)==1 and if_node is mode_scrape[0] and assignment in try_node.body and try_node in for_node.body and for_node in mode_scrape[0].body',
  '   if not exact_branch:diagnostics.append((call.lineno,call.col_offset+1,"repository scrape call must remain in the original scrape branch"))',
  '  if method=="start_crawl" and (len(mode_crawl)!=1 or parents.get(assignment) is not mode_crawl[0] or assignment not in mode_crawl[0].body):diagnostics.append((call.lineno,call.col_offset+1,"repository start_crawl call must remain in the original crawl branch"))',
  ' helper_calls=[node for node in nodes if isinstance(node,ast.Call) and any(isinstance(arg,ast.Name) and arg.id==contract["clientVariable"] for arg in node.args)]',
  ' exact_helper=len(helper_calls)==1 and isinstance(helper_calls[0].func,ast.Attribute) and isinstance(helper_calls[0].func.value,ast.Name) and helper_calls[0].func.value.id=="self" and helper_calls[0].func.attr=="_return_save_incremental_results" and len(helper_calls[0].args)>=1 and isinstance(helper_calls[0].args[0],ast.Name) and helper_calls[0].args[0].id==contract["clientVariable"]',
  ' if not exact_helper:diagnostics.append((function.lineno,function.col_offset+1,"repository client must be passed once to self._return_save_incremental_results"))',
  ' for name in [node for node in nodes if isinstance(node,ast.Name) and isinstance(node.ctx,ast.Load) and node.id==contract["mappingName"]]:',
  '  parent=parents.get(name);grandparent=parents.get(parent)',
  '  allowed=(isinstance(parent,ast.keyword) and parent.arg is None) or (is_timeout_target(parent,contract) and len(guards)==1 and grandparent is guards[0][1])',
  '  if not allowed:diagnostics.append((name.lineno,name.col_offset+1,"repository options mapping must not be aliased, read, or mutated outside its exact contract"))',
  ' for name in [node for node in nodes if isinstance(node,ast.Name) and isinstance(node.ctx,ast.Load) and node.id==contract["clientVariable"]]:',
  '  parent=parents.get(name);grandparent=parents.get(parent)',
  '  allowed=isinstance(parent,ast.Attribute) and parent.attr in method_calls and isinstance(grandparent,ast.Call) and grandparent.func is parent',
  '  allowed=allowed or (exact_helper and parent is helper_calls[0] and name is helper_calls[0].args[0])',
  '  if not allowed:diagnostics.append((name.lineno,name.col_offset+1,"repository client variable must not be aliased or used outside reviewed calls"))',
  'if call_contract:check_repository_calls(tree,call_contract)',
  'print(json.dumps({"diagnostics":[f"{request[\"path\"]}:{line}:{column}: {message}" for line,column,message in sorted(set(diagnostics))]}))',
].join('\n')

export async function findIncompletePythonResponseContracts(
  rootDir: string,
  paths: readonly string[],
  event: ActionableChangeEvent,
): Promise<string[]> {
  if (event.verificationStatus !== 'verified' || event.affectedLanguages.length !== 1
    || event.affectedLanguages[0] !== 'python') return []
  const clientTypes = event.operations.flatMap(operation => operation.operation === 'client'
    && typeof operation.newSymbol === 'string' ? [operation.newSymbol] : [])
  const evidence = event.evidence.flatMap(item => item.excerpt?.text ?? []).join('\n')
  const contractDiagnostics: string[] = []
  const callContract = repositoryCallContract(event, contractDiagnostics)
  const contracts = event.operations.flatMap(operation => {
    const details = operation.details
    if (details === undefined || !Object.prototype.hasOwnProperty.call(details, 'responseContract')) return []
    const value = details.responseContract
    if (!isResponseContract(value) || typeof operation.newSymbol !== 'string') {
      contractDiagnostics.push(`change operation ${operation.operation} declares a malformed Python response contract`)
      return []
    }
    const missingEvidence = value.evidenceBasis.filter(basis => !evidence.includes(basis))
    if (missingEvidence.length > 0) {
      throw new Error(`Python response contract lacks exact SDK evidence: ${missingEvidence.join(', ')}`)
    }
    return [{ method: operation.newSymbol, resultType: value.resultType,
      requiredAttributes: [...value.requiredAttributes],
      ...(value.itemType === undefined ? {} : { itemType: value.itemType }),
      ...(value.enforcement === undefined ? {} : { enforcement: value.enforcement }),
      ...(value.serialization === undefined ? {} : { serialization: value.serialization }) }]
  })
  if (contractDiagnostics.length > 0) return contractDiagnostics
  if (contracts.length === 0) return []
  const diagnostics: string[] = []
  for (const path of [...new Set(paths.filter(item => item.endsWith('.py')))]) {
    const content = await readFile(await resolveExistingPathInsideRepository(rootDir, path), 'utf8')
    const enforced = contracts.filter(contract => contract.enforcement?.sourcePath === path)
    const requiredAccesses = requiredPythonAccesses(enforced)
    const requiredSerializers = enforced.flatMap(contract => contract.serialization?.required === true
      ? [contract.resultType] : [])
    const result = spawnSync(process.env['AUTOMATED_API_PYTHON'] ?? 'python3', ['-I', '-c', analyzer], {
      input: JSON.stringify({ path, content, contracts, clientTypes, requiredAccesses, requiredSerializers,
        ...(callContract?.sourcePath === path ? { callContract } : {}) }),
      encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024,
      env: { PATH: process.env['PATH'], PYTHONIOENCODING: 'utf-8', PYTHONNOUSERSITE: '1' },
    })
    if (result.error || result.status !== 0) {
      diagnostics.push(`${path}: Python response-contract analysis failed closed: ${(result.stderr || result.error?.message || '').slice(0, 1_000)}`)
      continue
    }
    const parsed = JSON.parse(result.stdout) as { diagnostics?: unknown }
    if (!Array.isArray(parsed.diagnostics) || parsed.diagnostics.some(item => typeof item !== 'string')) {
      diagnostics.push(`${path}: Python response-contract analysis returned invalid output`)
      continue
    }
    diagnostics.push(...parsed.diagnostics)
  }
  return [...new Set(diagnostics)]
}

function repositoryCallContract(
  event: ActionableChangeEvent,
  diagnostics: string[],
): PythonRepositoryCallContract | undefined {
  const declared = event.operations.flatMap(operation =>
    operation.details !== undefined && Object.prototype.hasOwnProperty.call(operation.details, 'repositoryCallContract')
      ? [operation.details['repositoryCallContract']]
      : [])
  if (declared.length === 0) return undefined
  if (declared.length !== 1 || !isRepositoryCallContract(declared[0], event)) {
    diagnostics.push('change event declares a malformed or ambiguous Python repository call contract')
    return undefined
  }
  return declared[0]
}

function isRepositoryCallContract(
  value: unknown,
  event: ActionableChangeEvent,
): value is PythonRepositoryCallContract {
  if (typeof value !== 'object' || value === null) return false
  const item = value as Record<string, unknown>
  const entry = item.requiredMappingEntry
  const dependency = event.affectedDependencies[0]
  const operations = new Map(event.operations.map(operation => [operation.operation, operation]))
  const evidenceHashes = new Set(event.evidence.map(evidence => evidence.contentHash))
  return Object.keys(item).sort().join(',') === [
    'className', 'clientType', 'clientVariable', 'forbiddenClientKeywords', 'functionName', 'kind', 'mappingName',
    'repositoryBinding', 'requiredExpansionMethods', 'requiredMappingEntry', 'sourcePath',
  ].sort().join(',')
    && item.kind === 'langroid-firecrawl-options-v1'
    && item.sourcePath === 'langroid/parsing/url_loader.py'
    && (item.repositoryBinding === 'supportcontact584-png/autoapi-real-langroid-firecrawl-python@fcd37dea6fa4054ab5218fe98bb9a533a9a6328f'
      || item.repositoryBinding === 'sajsnddkn/autoapi-real-langroid-firecrawl-python@fcd37dea6fa4054ab5218fe98bb9a533a9a6328f'
      || item.repositoryBinding === 'APPNINJAS123/autoapi-real-langroid-firecrawl-python-public@fcd37dea6fa4054ab5218fe98bb9a533a9a6328f')
    && item.className === 'FirecrawlCrawler'
    && item.functionName === 'crawl'
    && item.clientType === 'Firecrawl'
    && item.clientVariable === 'app'
    && item.mappingName === 'params'
    && typeof entry === 'object' && entry !== null
    && Object.keys(entry as Record<string, unknown>).sort().join(',') === 'key,value'
    && (entry as Record<string, unknown>).key === 'timeout'
    && (entry as Record<string, unknown>).value === 'self.config.timeout'
    && sameStrings(item.requiredExpansionMethods, ['scrape', 'start_crawl'])
    && sameStrings(item.forbiddenClientKeywords, ['timeout'])
    && event.provider === 'firecrawl' && event.apiOrSdk === 'Firecrawl Python SDK'
    && event.oldVersion === '1.14.0' && event.newVersion === '4.31.0'
    && event.verificationStatus === 'verified' && sameStrings(event.affectedLanguages, ['python'])
    && sameStrings(event.recipeIds, ['firecrawl-python-v1-v2'])
    && event.affectedDependencies.length === 1 && dependency?.ecosystem === 'pypi'
    && dependency.name === 'firecrawl-py' && dependency.oldVersionRange === '==1.14.0'
    && dependency.newVersion === '4.31.0' && dependency.newArtifactSha256 === reviewedLangroidEvidenceHashes[2]
    && event.operations.length === 4
    && operations.get('client')?.oldSymbol === 'FirecrawlApp' && operations.get('client')?.newSymbol === 'Firecrawl'
    && operations.get('scrape')?.oldSymbol === 'scrape_url' && operations.get('scrape')?.newSymbol === 'scrape'
    && operations.get('start_crawl')?.oldSymbol === 'async_crawl_url'
    && operations.get('start_crawl')?.newSymbol === 'start_crawl'
    && operations.get('crawl_status')?.oldSymbol === 'check_crawl_status'
    && operations.get('crawl_status')?.newSymbol === 'get_crawl_status'
    && evidenceHashes.size === reviewedLangroidEvidenceHashes.length
    && reviewedLangroidEvidenceHashes.every(hash => evidenceHashes.has(hash))
}

function sameStrings(left: unknown, right: readonly string[]): boolean {
  return Array.isArray(left) && left.length === right.length
    && left.every((value, index) => value === right[index])
}

function isResponseContract(value: unknown): value is {
  language: 'python'; resultType: string; requiredAttributes: string[]; forbidMappingAccess: true;
  itemType?: string; evidenceBasis: string[]; serialization?: PythonResponseContract['serialization'];
  enforcement?: PythonResponseContract['enforcement'];
} {
  if (typeof value !== 'object' || value === null) return false
  const item = value as Record<string, unknown>
  const serialization = item.serialization
  const validSerialization = serialization === undefined || (typeof serialization === 'object' && serialization !== null
    && (serialization as Record<string, unknown>).method === 'model_dump'
    && (serialization as Record<string, unknown>).mode === 'json'
    && (serialization as Record<string, unknown>).consumer === 'json.dump'
    && ((serialization as Record<string, unknown>).required === undefined
      || (serialization as Record<string, unknown>).required === true))
  const enforcement = item.enforcement
  const validEnforcement = enforcement === undefined || (typeof enforcement === 'object' && enforcement !== null
    && (enforcement as Record<string, unknown>).requiredAttributes === true
    && typeof (enforcement as Record<string, unknown>).sourcePath === 'string'
    && typeof (enforcement as Record<string, unknown>).repositoryBinding === 'string')
  return item.language === 'python' && typeof item.resultType === 'string' && item.resultType.length > 0
    && (item.itemType === undefined || typeof item.itemType === 'string')
    && item.forbidMappingAccess === true && Array.isArray(item.requiredAttributes)
    && item.requiredAttributes.length > 0 && item.requiredAttributes.every(entry => typeof entry === 'string')
    && Array.isArray(item.evidenceBasis) && item.evidenceBasis.length > 0
    && item.evidenceBasis.every(entry => typeof entry === 'string') && validSerialization && validEnforcement
}

function requiredPythonAccesses(contracts: readonly PythonResponseContract[]): Record<string, string[]> {
  const accesses = new Map<string, Set<string>>()
  const require = (type: string, attribute: string) => {
    if (!accesses.has(type)) accesses.set(type, new Set())
    accesses.get(type)!.add(attribute)
  }
  for (const contract of contracts) {
    if (contract.enforcement?.requiredAttributes !== true) continue
    for (const required of contract.requiredAttributes) {
      const parts = required.replaceAll('[]', '').split('.')
      const first = parts[0]
      if (first === undefined || first.length === 0) continue
      require(contract.resultType, first)
      if (first === 'metadata' && parts[1] !== undefined) require('DocumentMetadata', parts[1])
      if (first === 'data' && contract.itemType !== undefined && parts[1] !== undefined) {
        require(contract.itemType, parts[1])
        if (parts[1] === 'metadata' && parts[2] !== undefined) require('DocumentMetadata', parts[2])
      }
    }
  }
  return Object.fromEntries([...accesses].map(([type, attributes]) => [type, [...attributes].sort()]))
}
