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
        },

        // CSS minification with PostCSS and cssnano (supports modern CSS)
        postcss: {
            options: {
                processors: [
                    require("cssnano")({
                        preset: "default"
                    })
                ]
            },
            admin: {
                src: "assets/css/admin.css",
                dest: "assets/css/admin.min.css"
            },
            passwordValidation: {
                src: "assets/css/password-validation.css", 
                dest: "assets/css/password-validation.min.css"
            },
            variables: {
                src: "assets/css/variables.css",
                dest: "assets/css/variables.min.css"
            }
        }
    });

    // Load grunt plugins
    grunt.loadNpmTasks("grunt-postcss");
    grunt.loadNpmTasks("grunt-contrib-uglify");

    // Register tasks
    grunt.registerTask("css", ["postcss"]);
    grunt.registerTask("js", ["uglify"]);
    grunt.registerTask("default", ["postcss", "uglify"]);
    grunt.registerTask("minify", ["postcss", "uglify"]);

    // Custom task to show minification results
    grunt.registerTask("build", "Build minified assets", function() {
        grunt.task.run(["postcss", "uglify"]);
        grunt.log.writeln("");
        grunt.log.writeln("✨ Asset minification completed successfully!");
        grunt.log.writeln("📦 Generated files:");
        grunt.log.writeln("   • assets/css/admin.min.css");
        grunt.log.writeln("   • assets/css/password-validation.min.css");
        grunt.log.writeln("   • assets/css/variables.min.css");
        grunt.log.writeln("   • assets/js/admin.min.js");
        grunt.log.writeln("   • assets/js/password-validation.min.js");
        grunt.log.writeln("");
        grunt.log.writeln("🚀 Ready for production build!");
    });
};
