"use strict";
module.exports = function (grunt) {
    // Load package.json
    grunt.file.defaultEncoding = "utf8";
    grunt.file.preserveBOM = false;

    grunt.initConfig({
        // Read package.json for metadata
        pkg: grunt.file.readJSON("package.json"),

        // JavaScript minification with UglifyJS
        uglify: {
            options: {
                banner:
                    "/*! <%= pkg.name %> - v<%= pkg.version %> - " +
                    "<%= grunt.template.today(\"yyyy-mm-dd\") %> */\n",
                report: "gzip",
                compress: {
                    drop_console: false,  // Keep console logs for WordPress debug
                    drop_debugger: true,
                    dead_code: true,
                    unused: true
                },
                mangle: {
                    reserved: ["jQuery", "$", "window", "document"]  // Preserve WordPress globals
                },
                sourceMap: false,  // No source maps for production
                preserveComments: function(node, comment) {
                    // Preserve license headers and important comments
                    return comment.value.match(/^!|@preserve|@license|@cc_on/i);
                }
            },
            admin: {
                files: {
                    "assets/js/admin.min.js": ["assets/js/admin.js"]
                }
            },
            passwordValidation: {
                files: {
                    "assets/js/password-validation.min.js": ["assets/js/password-validation.js"]
                }
            },
            updateCheck: {
                files: {
                    "assets/js/update-check.min.js": ["assets/js/update-check.js"]
                }
            }
        }
    });

    // Load grunt plugins
    grunt.loadNpmTasks("grunt-contrib-uglify");

    // Register tasks
    grunt.registerTask("js", ["uglify"]);
    grunt.registerTask("default", ["uglify"]);
    grunt.registerTask("minify", ["uglify"]);

    // Custom task to show minification results
    grunt.registerTask("build", "Build minified assets", function() {
        grunt.task.run(["uglify"]);
        grunt.log.writeln("");
        grunt.log.writeln("✨ JavaScript minification completed successfully!");
        grunt.log.writeln("📦 Generated files:");
        grunt.log.writeln("   • assets/js/admin.min.js");
        grunt.log.writeln("   • assets/js/password-validation.min.js");
        grunt.log.writeln("   • assets/js/update-check.min.js");
        grunt.log.writeln("");
        grunt.log.writeln("ℹ CSS minification: Run 'npm run minify:css' separately");
        grunt.log.writeln("🚀 Ready for production build!");
    });
};
