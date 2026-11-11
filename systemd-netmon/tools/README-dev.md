Dev-only asset rebuild (not needed to run netmon):

    npm i tailwindcss@3 lucide-static@0.460.0
    python3 tools/build_icons.py node_modules/lucide-static/icons
    cd tools && npx tailwindcss -c tailwind.config.js -i in.css -o ../static/app.css --minify
