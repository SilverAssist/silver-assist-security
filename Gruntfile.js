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
            }
        },

        // CSS minification with clean-css
        cssmin: {
            options: {
                banner: "/*! <%= pkg.name %> - v<%= pkg.version %> - " +
                       "<%= grunt.template.today(\"yyyy-mm-dd\") %> */\n",
                compatibility: "ie9",  // Support IE9+ for WordPress compatibility
                report: "gzip",
                level: {
                    1: {
                        all: true,
                        normalizeUrls: false  // Don't change URLs
                    },
                    2: {
                        all: true,
                        removeDuplicateRules: true,
                        reduceNonAdjacentRules: true,
                        mergeAdjacentRules: true,
                        mergeIntoShorthands: true,
                        mergeMedia: true,
                        mergeNonAdjacentRules: true,
                        mergeSemantically: false,  // Keep semantic meaning
                        overrideProperties: true,
                        removeEmpty: true,
                        reduceNonAdjacentRules: true,
                        removeDuplicateFontRules: true,
                        removeDuplicateMediaBlocks: true,
                        removeDuplicateRules: true,
                        removeUnusedAtRules: false,  // Keep all @rules for WordPress compatibility
                        restructureRules: true
                    }
                }
            },
            admin: {
                files: {
                    "assets/css/admin.min.css": ["assets/css/admin.css"]
                }
            },
            passwordValidation: {
                files: {
                    "assets/css/password-validation.min.css": ["assets/css/password-validation.css"]
                }
            },
            variables: {
                files: {
                    "assets/css/variables.min.css": ["assets/css/variables.css"]
                }
            }
        }
    });

    // Load grunt plugins
    grunt.loadNpmTasks("grunt-contrib-cssmin");
    grunt.loadNpmTasks("grunt-contrib-uglify");

    // Register tasks
    grunt.registerTask("css", ["cssmin"]);
    grunt.registerTask("js", ["uglify"]);
    grunt.registerTask("default", ["cssmin", "uglify"]);
    grunt.registerTask("minify", ["cssmin", "uglify"]);

    // Custom task to show minification results
    grunt.registerTask("build", "Build minified assets", function() {
        grunt.task.run(["cssmin", "uglify"]);
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
