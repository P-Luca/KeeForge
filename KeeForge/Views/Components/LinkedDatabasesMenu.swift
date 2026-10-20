import SwiftUI

/// Switches to a database linked from the session's KeePassXC `AutoOpen`
/// group. Renders nothing when there are no links.
struct LinkedDatabasesMenu: View {
    let viewModel: DatabaseViewModel

    var body: some View {
        if viewModel.autoOpenLinks.isEmpty == false {
            Menu {
                Section("Linked Databases") {
                    ForEach(viewModel.autoOpenLinks) { link in
                        Button(link.reference.displayName, systemImage: "cylinder.split.1x2") {
                            Task { await viewModel.requestAutoOpenSwitch(to: link) }
                        }
                    }
                }
            } label: {
                Image(systemName: "link")
            }
            .menuIndicator(.hidden)
            .accessibilityLabel("Linked Databases")
            .macHelp(String(localized: "Linked Databases"))
            .accessibilityIdentifier("database.linked-databases")
        }
    }
}
