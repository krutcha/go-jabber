package main

import (
	"gtk"
	"gdk"
	"os"
)

func main() {
	//GTK init stuff
	gdk.ThreadsInit()
	gtk.Init(&os.Args)

	//Create a main Window
	window := gtk.Window(gtk.GTK_WINDOW_TOPLEVEL)
	window.SetTitle("Go-Jabber-gtk")
	
	//handle "destroy" event
	window.Connect("destroy", func() {
		gtk.MainQuit()
	},
		nil)

	//vertical container for textview 
	vbox := gtk.VBox(false, 1)

	//Main chat text window, with scrollbar
	scrolledwin := gtk.ScrolledWindow(nil, nil)

	//Main the textview inside the scrollable window
	chattext := gtk.TextView()
	chattext.SetEditable(false)
	chattext.SetCursorVisible(false)
	//add text view to scrollable window
	scrolledwin.Add(chattext)

	commandtext := gtk.TextView()
	commandtext.SetEditable(true)
	commandtext.SetCursorVisible(true)
	
	//add scrollable window to vertical container
	vbox.Add(scrolledwin)

	//add command text under chat text
	vbox.PackEnd(commandtext, false,false, 0)

	window.Add(vbox)
	window.SetSizeRequest(800, 500)
	window.ShowAll()

	/*
	//handle to the text view's text!
	chatbuffer := chattext.GetBuffer()

	var iter gtk.GtkTextIter
	chatbuffer.GetStartIter(&iter)
	tag := chatbuffer.CreateTag("blue", map[string]string{
		"foreground": "#0000FF", "weight": "700"})
	for i := 0; ; i++ {
		//icon := data["user"].(map[string]interface{})["profile_image_url"].(string)
		//buffer.InsertPixbuf(&iter, url2pixbuf(icon))
		name := "hi" + string(i)
		text := "lo" + string(i)
		//buffer.Insert(&iter, " ")
		chatbuffer.InsertWithTag(&iter, name, tag)
		chatbuffer.Insert(&iter, ":"+text+"\n")
	}*/

	gtk.Main()
}
