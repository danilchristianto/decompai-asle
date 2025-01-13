import gradio as gr
import src.main as main

with gr.Blocks(css=main.CSS, title="Binary Analysis Agent") as demo:
    main.demo_block()
demo.launch()