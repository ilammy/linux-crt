/*
 * CreateRemoteThread for Linux
 *
 * Copyright (c) 2018, ilammy
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 */

#include <glib.h>
#include <gtk/gtk.h>

static void input_purpose_changed(GtkEntry *entry)
{
	GtkInputPurpose purpose = gtk_entry_get_input_purpose(entry);

	if (purpose == GTK_INPUT_PURPOSE_PASSWORD) {
		gtk_entry_set_icon_activatable(entry, GTK_ENTRY_ICON_PRIMARY,
			TRUE);
		gtk_entry_set_icon_from_icon_name(entry, GTK_ENTRY_ICON_PRIMARY,
			"list-remove");
	} else {
		gtk_entry_set_icon_activatable(entry, GTK_ENTRY_ICON_PRIMARY,
			FALSE);
		gtk_entry_set_icon_from_icon_name(entry, GTK_ENTRY_ICON_PRIMARY,
			NULL);
	}
}

static void icon_pressed(GtkEntry *entry, GtkEntryIconPosition position)
{
	if (position != GTK_ENTRY_ICON_PRIMARY)
		return;

	gtk_entry_set_visibility(entry, TRUE);
	gtk_entry_set_icon_from_icon_name(entry, GTK_ENTRY_ICON_PRIMARY,
		"list-add");
}

static void icon_released(GtkEntry *entry, GtkEntryIconPosition position)
{
	if (position != GTK_ENTRY_ICON_PRIMARY)
		return;

	gtk_entry_set_visibility(entry, FALSE);
	gtk_entry_set_icon_from_icon_name(entry, GTK_ENTRY_ICON_PRIMARY,
		"list-remove");
}

static void (*old_gtk_entry_constructed)(GObject *object);

static void new_gtk_entry_constructed(GObject *object)
{
	old_gtk_entry_constructed(object);

	GtkEntry *entry = GTK_ENTRY(object);

	/*
	 * Listen to "input-purpose" property to know when the entry
	 * is switched into "password input" mode. Listen to icon
	 * events as well to show-hide the password input.
	 */

	g_signal_connect(entry, "notify::input-purpose",
		G_CALLBACK(input_purpose_changed), NULL);

	g_signal_connect(entry, "icon-press",
		G_CALLBACK(icon_pressed), NULL);

	g_signal_connect(entry, "icon-release",
		G_CALLBACK(icon_released), NULL);
}

static void hook_gtk_entry_constructor(void)
{
	GTypeClass *entry_type_class = g_type_class_peek(GTK_TYPE_ENTRY);
	GObjectClass *entry_object_class = G_OBJECT_CLASS(entry_type_class);

	/*
	 * "constructed" callback is called after instantiation is complete.
	 * Save the previous one so that we can call the original handler.
	 */
	old_gtk_entry_constructed = entry_object_class->constructed;
	entry_object_class->constructed = new_gtk_entry_constructed;
}

static gboolean actual_entry(gpointer _arg)
{
	hook_gtk_entry_constructor();

	/*
	 * Return FALSE to tell glib that we don't want to run this
	 * callback again on the main event loop.
	 */
	return FALSE;
}

void entry(void)
{
	/*
	 * The entry point is executed on a brand new thread, we need
	 * to schedule our callback on GTK's main event loop in order
	 * to do any GUI-related stuff.
	 */
	g_idle_add_full(G_PRIORITY_DEFAULT_IDLE, actual_entry, NULL, NULL);
}
