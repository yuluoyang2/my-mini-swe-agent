#include "helper.hpp"

#include <algorithm>
#include <filesystem>
#include <future>
#include <memory>
#include <unordered_set>
#include <vector>

using namespace clang;
using namespace clang::tooling;

namespace {

llvm::cl::OptionCategory analyzer_category("kernel-source-analyzer options");
llvm::cl::opt<std::string>
    compile_commands_path("p", llvm::cl::desc("Path to compile_commands.json"),
                          llvm::cl::Required, llvm::cl::cat(analyzer_category));
llvm::cl::opt<std::string>
    out_dir("out-dir", llvm::cl::desc("Directory for generated JSONL files"),
            llvm::cl::init("."), llvm::cl::cat(analyzer_category));
llvm::cl::opt<int> jobs("jobs", llvm::cl::desc("Maximum concurrent files"),
                        llvm::cl::init(32), llvm::cl::cat(analyzer_category));

std::string record_kind(const RecordDecl *decl) {
  if (decl->isUnion())
    return "union";
  if (decl->isStruct())
    return "struct";
  if (decl->isClass())
    return "class";
  return "record";
}

std::string field_name_from_designator(const DesignatedInitExpr *expr) {
  for (const DesignatedInitExpr::Designator &designator : expr->designators()) {
    if (designator.isFieldDesignator() && designator.getFieldName())
      return designator.getFieldName()->getName().str();
  }
  return "";
}

bool has_suffix(const std::string &value, const std::string &suffix) {
  return value.size() >= suffix.size() &&
         value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

ArgumentsAdjuster get_kernel_argument_adjuster() {
  ArgumentsAdjuster base = combineAdjusters(
      combineAdjusters(getClangStripDependencyFileAdjuster(),
                       getClangStripOutputAdjuster()),
      getClangSyntaxOnlyAdjuster());
  return [base](const CommandLineArguments &args, llvm::StringRef filename) {
    CommandLineArguments adjusted = base(args, filename);
    CommandLineArguments result;
    for (size_t i = 0; i < adjusted.size(); ++i) {
      llvm::StringRef arg(adjusted[i]);
      if (arg == "-M" || arg == "-MM" || arg == "-MD" || arg == "-MMD" ||
          arg == "-MG" || arg == "-MP")
        continue;
      if (arg == "-MF" || arg == "-MT" || arg == "-MQ" || arg == "-MJ") {
        ++i;
        continue;
      }
      if (arg.startswith("-MF") || arg.startswith("-MT") ||
          arg.startswith("-MQ") || arg.startswith("-MJ") ||
          arg.startswith("-Wp,-M"))
        continue;
      result.push_back(adjusted[i]);
    }
    return result;
  };
}

class KernelSourceVisitor : public RecursiveASTVisitor<KernelSourceVisitor> {
public:
  explicit KernelSourceVisitor(ASTContext *context, OutputWriter *writer)
      : context(context), writer(writer) {}

  bool VisitFunctionDecl(FunctionDecl *decl) {
    if (decl->isThisDeclarationADefinition() && !decl->getNameAsString().empty())
      writer->write_decl(decl, "func.jsonl");
    return true;
  }

  bool VisitRecordDecl(RecordDecl *decl) {
    if (decl->isThisDeclarationADefinition() && !decl->getNameAsString().empty())
      writer->write_decl(decl, "struct.jsonl", record_kind(decl));
    return true;
  }

  bool VisitEnumDecl(EnumDecl *decl) {
    if (decl->isThisDeclarationADefinition() && !decl->getNameAsString().empty())
      writer->write_decl(decl, "enum.jsonl");
    return true;
  }

  bool VisitTypedefDecl(TypedefDecl *decl) {
    QualType type = decl->getUnderlyingType();
    if (const auto *enum_type = type->getAs<EnumType>()) {
      writer->write_decl(decl, "enum-typedef.jsonl", "enum_typedef",
                         enum_type->getDecl()->getNameAsString());
    } else if (const auto *record_type = type->getAs<RecordType>()) {
      writer->write_decl(decl, "struct-typedef.jsonl", "struct_typedef",
                         record_type->getDecl()->getNameAsString());
    }
    return true;
  }

  bool VisitVarDecl(VarDecl *decl) {
    if (!context->getSourceManager().isInMainFile(decl->getBeginLoc()))
      return true;
    if (!decl->hasInit() || decl->getNameAsString().empty())
      return true;
    const auto *init_list = dyn_cast<InitListExpr>(decl->getInit());
    const auto *record_decl = decl->getType()->getAsRecordDecl();
    if (!init_list || !record_decl)
      return true;

    auto field_it = record_decl->field_begin();
    for (unsigned i = 0; i < init_list->getNumInits(); ++i) {
      const Expr *init = init_list->getInit(i);
      std::string field;
      if (const auto *designated = dyn_cast<DesignatedInitExpr>(init)) {
        field = field_name_from_designator(designated);
        init = designated->getInit();
      } else {
        if (field_it == record_decl->field_end())
          break;
        field = (*field_it)->getNameAsString();
        ++field_it;
      }

      const FunctionDecl *handler = find_function_ref(init);
      if (!handler || field.empty())
        continue;

      const SourceManager &source_manager = context->getSourceManager();
      std::string file = get_file_path(source_manager, init->getBeginLoc());
      unsigned line = get_line(source_manager, init->getBeginLoc());
      unsigned table_line = get_line(source_manager, decl->getBeginLoc());
      std::string table = decl->getNameAsString();
      std::string table_type = decl->getType().getAsString();
      std::string table_key = file + ":" + std::to_string(table_line) + ":" +
                              table + ":" + table_type;

      std::string json = "{";
      json += "\"kind\":\"ops_field\"";
      json += ",\"table\":\"" + json_escape(table) + "\"";
      json += ",\"table_type\":\"" + json_escape(table_type) + "\"";
      json += ",\"field\":\"" + json_escape(field) + "\"";
      json += ",\"handler\":\"" + json_escape(handler->getNameAsString()) + "\"";
      json += ",\"file\":\"" + json_escape(file) + "\"";
      json += ",\"filename\":\"" + json_escape(file + ":" + std::to_string(line)) + "\"";
      json += ",\"line\":" + std::to_string(line);
      json += ",\"table_line\":" + std::to_string(table_line);
      json += ",\"table_key\":\"" + json_escape(table_key) + "\"";
      json += ",\"source\":\"" +
              json_escape(get_source_text(source_manager, context->getLangOpts(),
                                          init->getSourceRange())) +
              "\"";
      json += ",\"table_source\":\"" + json_escape(get_decl_source(decl)) + "\"";
      json += "}";
      writer->write_jsonl("ops.jsonl", json,
                          table_key + "\x1f" + field + "\x1f" +
                              handler->getNameAsString());
    }
    return true;
  }

private:
  ASTContext *context;
  OutputWriter *writer;
};

class KernelSourceConsumer : public ASTConsumer {
public:
  explicit KernelSourceConsumer(ASTContext *context, OutputWriter *writer)
      : visitor(context, writer) {}

  void HandleTranslationUnit(ASTContext &context) override {
    visitor.TraverseDecl(context.getTranslationUnitDecl());
  }

private:
  KernelSourceVisitor visitor;
};

class KernelSourceAction : public ASTFrontendAction {
public:
  explicit KernelSourceAction(OutputWriter *writer) : writer(writer) {}

  std::unique_ptr<ASTConsumer>
  CreateASTConsumer(CompilerInstance &compiler, llvm::StringRef) override {
    return std::make_unique<KernelSourceConsumer>(&compiler.getASTContext(),
                                                  writer);
  }

private:
  OutputWriter *writer;
};

class KernelSourceActionFactory : public FrontendActionFactory {
public:
  explicit KernelSourceActionFactory(OutputWriter *writer) : writer(writer) {}

  std::unique_ptr<FrontendAction> create() override {
    return std::make_unique<KernelSourceAction>(writer);
  }

private:
  OutputWriter *writer;
};

} // namespace

int main(int argc, const char **argv) {
  llvm::cl::ParseCommandLineOptions(argc, argv);

  std::string error;
  auto database = JSONCompilationDatabase::loadFromFile(
      compile_commands_path, error, JSONCommandLineSyntax::AutoDetect);
  if (!database) {
    llvm::errs() << "Error loading compile_commands.json: " << error << "\n";
    return 1;
  }

  std::vector<std::string> sources;
  std::unordered_set<std::string> seen_sources;
  for (const CompileCommand &command : database->getAllCompileCommands()) {
    std::filesystem::path source(command.Filename);
    if (source.is_relative())
      source = std::filesystem::path(command.Directory) / source;
    std::string source_path = source.lexically_normal().string();
    if ((has_suffix(source_path, ".c") || has_suffix(source_path, ".h")) &&
        seen_sources.insert(source_path).second)
      sources.push_back(source_path);
  }

  OutputWriter writer(out_dir.getValue());
  KernelSourceActionFactory factory(&writer);
  std::vector<std::future<int>> futures;
  int max_jobs = std::max(1, jobs.getValue());
  ArgumentsAdjuster adjuster = get_kernel_argument_adjuster();
  size_t done = 0;
  size_t failed = 0;

  llvm::errs() << "Analyzing " << sources.size() << " source files with "
               << max_jobs << " jobs\n";

  auto collect_one = [&]() {
    int status = futures.front().get();
    futures.erase(futures.begin());
    ++done;
    if (status != 0)
      ++failed;
    if (done % 100 == 0 || done == sources.size())
      llvm::errs() << "Progress: " << done << "/" << sources.size()
                   << " files, failed: " << failed << "\n";
  };

  for (const std::string &source : sources) {
    while (static_cast<int>(futures.size()) >= max_jobs)
      collect_one();
    futures.push_back(std::async(std::launch::async, [&database, &factory,
                                                       &adjuster, source]() {
      ClangTool tool(*database, std::vector<std::string>{source});
      tool.appendArgumentsAdjuster(adjuster);
      return tool.run(&factory);
    }));
  }
  while (!futures.empty())
    collect_one();

  llvm::errs() << "Finished analyzing " << done << " files, failed: " << failed
               << "\n";
  return 0;
}
