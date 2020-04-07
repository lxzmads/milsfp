#include <gtk/gtk.h>

GtkWidget *goButton;
GtkWidget *mainText;
GtkWidget *goEntry;

int main(int argc, char *argv[])
{
    GtkBuilder      *builder; 
    GtkWidget       *window;

    gtk_init(&argc, &argv);

    builder = gtk_builder_new();
    gtk_builder_add_from_file (builder, "glade/main.glade", NULL);

    window = GTK_WIDGET(gtk_builder_get_object(builder, "mainWindow"));
    goButton = GTK_WIDGET(gtk_builder_get_object(builder, "goButton"));
    goEntry = GTK_WIDGET(gtk_builder_get_object(builder, "goEntry"));
    mainText = GTK_WIDGET(gtk_builder_get_object(builder, "mainText"));

    gtk_builder_connect_signals(builder, NULL);
    
    // get pointers to the two labels

    g_object_unref(builder);

    gtk_widget_show(window);                
    gtk_main();

    return 0;
}

// called when button is clicked
void onGoButtonClick()
{
	const gchar *command;
	GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(mainText));

	command = gtk_entry_get_text(GTK_ENTRY(goEntry));
	gtk_text_buffer_set_text(buf, command, -1);
}

// called when window is closed
void on_window_main_destroy()
{
    gtk_main_quit();
}
