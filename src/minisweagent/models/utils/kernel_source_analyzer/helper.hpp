#ifndef MINISWEAGENT_KERNEL_SOURCE_ANALYZER_HELPER_HPP
#define MINISWEAGENT_KERNEL_SOURCE_ANALYZER_HELPER_HPP

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Lex/Lexer.h"
#include "clang/Tooling/JSONCompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"

#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_set>

struct OutputWriter {
  explicit OutputWriter(std::filesystem::path out_dir);

  void write_decl(const clang::NamedDecl *decl, const std::string &file_name,
                  const std::string &kind = "",
                  const std::string &alias = "");
  void write_jsonl(const std::string &file_name, const std::string &json,
                   const std::string &dedupe_key = "");

  std::filesystem::path out_dir;
  std::mutex mutex;
  std::unordered_set<std::string> seen;
};

std::string json_escape(const std::string &value);
std::string get_source_text(const clang::SourceManager &source_manager,
                            clang::LangOptions lang_options,
                            clang::SourceRange source_range);
std::string get_decl_source(const clang::NamedDecl *decl);
std::string get_filename_with_line(const clang::NamedDecl *decl);
std::string get_file_path(const clang::SourceManager &source_manager,
                          clang::SourceLocation loc);
unsigned get_line(const clang::SourceManager &source_manager,
                  clang::SourceLocation loc);
const clang::FunctionDecl *find_function_ref(const clang::Expr *expr);

#endif
