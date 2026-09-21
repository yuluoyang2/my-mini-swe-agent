#include "helper.hpp"

using namespace clang;

OutputWriter::OutputWriter(std::filesystem::path out_dir)
    : out_dir(std::move(out_dir)) {
  std::filesystem::create_directories(this->out_dir);
}

void OutputWriter::write_jsonl(const std::string &file_name,
                               const std::string &json,
                               const std::string &dedupe_key) {
  std::lock_guard<std::mutex> lock(mutex);
  if (!seen.insert(file_name + "\x1f" +
                   (dedupe_key.empty() ? json : dedupe_key))
           .second)
    return;
  std::ofstream output(out_dir / file_name, std::ios_base::app);
  output << json << "\n";
}

void OutputWriter::write_decl(const NamedDecl *decl, const std::string &file_name,
                              const std::string &kind,
                              const std::string &alias) {
  std::string name = decl->getNameAsString();
  std::string filename = get_filename_with_line(decl);
  std::string json = "{";
  json += "\"name\":\"" + json_escape(name) + "\"";
  json += ",\"filename\":\"" + json_escape(filename) + "\"";
  json += ",\"source\":\"" + json_escape(get_decl_source(decl)) + "\"";
  if (!kind.empty())
    json += ",\"kind\":\"" + json_escape(kind) + "\"";
  if (!alias.empty())
    json += ",\"alias\":\"" + json_escape(alias) + "\"";
  json += "}";
  write_jsonl(file_name, json, name + "\x1f" + filename + "\x1f" + kind + "\x1f" +
                                   alias);
}

std::string json_escape(const std::string &value) {
  std::string out;
  for (char c : value) {
    switch (c) {
    case '\\':
      out += "\\\\";
      break;
    case '"':
      out += "\\\"";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      out += c;
      break;
    }
  }
  return out;
}

std::string get_source_text(const SourceManager &source_manager,
                            LangOptions lang_options,
                            SourceRange source_range) {
  SourceLocation begin = source_manager.getSpellingLoc(source_range.getBegin());
  SourceLocation end = source_manager.getSpellingLoc(source_range.getEnd());
  if (begin.isInvalid() || end.isInvalid())
    return "";
  bool invalid = false;
  llvm::StringRef text = Lexer::getSourceText(
      CharSourceRange::getTokenRange(begin, end), source_manager, lang_options,
      &invalid);
  return invalid ? "" : text.str();
}

std::string get_decl_source(const NamedDecl *decl) {
  return get_source_text(decl->getASTContext().getSourceManager(),
                         decl->getASTContext().getLangOpts(),
                         decl->getSourceRange());
}

std::string get_file_path(const SourceManager &source_manager,
                          SourceLocation loc) {
  SourceLocation spelling_loc = source_manager.getSpellingLoc(loc);
  if (const FileEntry *file_entry =
          source_manager.getFileEntryForID(source_manager.getFileID(spelling_loc)))
    return file_entry->tryGetRealPathName().str();
  return spelling_loc.printToString(source_manager);
}

unsigned get_line(const SourceManager &source_manager, SourceLocation loc) {
  return source_manager.getSpellingLineNumber(source_manager.getSpellingLoc(loc));
}

std::string get_filename_with_line(const NamedDecl *decl) {
  const SourceManager &source_manager = decl->getASTContext().getSourceManager();
  return get_file_path(source_manager, decl->getBeginLoc()) + ":" +
         std::to_string(get_line(source_manager, decl->getBeginLoc()));
}

const FunctionDecl *find_function_ref(const Expr *expr) {
  if (!expr)
    return nullptr;
  expr = expr->IgnoreParenImpCasts();
  if (const auto *unary = dyn_cast<UnaryOperator>(expr)) {
    if (unary->getOpcode() == UO_AddrOf)
      return find_function_ref(unary->getSubExpr());
  }
  if (const auto *decl_ref = dyn_cast<DeclRefExpr>(expr)) {
    if (const auto *func = dyn_cast<FunctionDecl>(decl_ref->getDecl()))
      return func;
  }
  for (const Stmt *child : expr->children()) {
    if (const auto *child_expr = dyn_cast_or_null<Expr>(child)) {
      if (const FunctionDecl *func = find_function_ref(child_expr))
        return func;
    }
  }
  return nullptr;
}
